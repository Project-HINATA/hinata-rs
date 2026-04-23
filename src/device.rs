use crate::error::{Error, HinataResult, PlatformError, ProtocolError};
use crate::message::{InMessage, OutMessage, Subscription, UnSubscribePolicy};
use crate::pn532::{Pn532, Pn532Command, Pn532Direction, Pn532Packet, Pn532Port};
use crate::types::HidDevicePath;
use async_trait::async_trait;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub(crate) struct Info {
    pub firmware_timestamp: u32,
    pub firmware_commit_hash: Option<[u8; 4]>,
    pub chip_id: Option<[u8; 4]>,

    pub instance_id: String,
    pub path: HidDevicePath,
    pub device_name: String,
    pub pid: u16,
}

#[derive(Debug)]
pub(crate) struct Config {
    pub sega_brightness: u8,
    pub sega_rapid_scan: bool,
}

// --- Device Implementation ---

#[derive(Debug)]
pub struct HinataDevice {
    info: Info,
    config: Config,
    loop_handler: Option<JoinHandle<()>>,

    tx: Sender<InMessage>,
}

#[async_trait]
impl Pn532Port for HinataDevice {
    async fn request(&mut self, pn532_cmd: Pn532Command, payload: &[u8]) -> HinataResult<Vec<u8>> {
        let (subscription, mut rx) = Subscription::new(UnSubscribePolicy::SpecificNotOn(4, 0));
        let packet = Pn532Packet::new(Pn532Direction::HostToPn532, pn532_cmd, payload.to_vec());
        let mut send = vec![1, 0xE2];
        send.extend_from_slice(&packet.to_bytes());

        let _ = self
            .tx
            .send(InMessage::SendPacketAndSubscribe(send, subscription))
            .await;

        loop {
            let res = Self::receive_packet(&mut rx, Duration::from_millis(200)).await?;
            let len = res.get(4).ok_or(Error::Protocol(ProtocolError::PacketTooShort))?;
            let len_rev = res.get(5).ok_or(Error::Protocol(ProtocolError::PacketTooShort))?;
            if *len == 0 && *len_rev == 0xFF { // ack
                continue
            } else if (*len + *len_rev) & 0xFF != 0 {
                return Err(Error::Protocol(ProtocolError::InvalidLcs));
            }
            if *len > 0 {
                let res_packet = Pn532Packet::from_bytes(&res[1..])?;
                return Ok(res_packet.payload);
            }
        }
    }
}

impl HinataDevice {
    pub(crate) fn new(
        info: Info,
        config: Config,
        loop_handler: Option<JoinHandle<()>>,
        tx: Sender<InMessage>,
    ) -> Self {
        Self {
            info,
            config,
            loop_handler,
            tx,
        }
    }

    pub fn get_instance_id(&self) -> String {
        self.info.instance_id.to_string()
    }

    async fn receive_packet(
        rx: &mut Receiver<OutMessage>,
        timeout: Duration,
    ) -> HinataResult<Vec<u8>> {
        tokio::select! {
            message = rx.recv() => {
                if let Some(data) = message {
                    match data {
                        OutMessage::Response(data) => Ok(data),
                        OutMessage::DeviceDisconnect => Err(Error::Disconnected("Device disconnected".into()))
                    }
                } else {
                    Err(Error::Disconnected("Subscribe channel disconnected".into()))
                }
            },
            _timeout = tokio::time::sleep(timeout) => { Err(Error::Timeout("Wait response timeout".into())) }

        }
    }

    async fn request_without_response(&mut self, cmd: u8, payload: &[u8]) {
        let mut packet = vec![1, cmd];
        packet.extend_from_slice(payload);
        let _ = self.tx.send(InMessage::SendPacket(packet)).await;
    }
    async fn request(&mut self, cmd: u8, payload: &[u8]) -> HinataResult<Vec<u8>> {
        let mut packet = vec![1, cmd];
        packet.extend_from_slice(payload);
        let (subscription, mut rx) = Subscription::new(UnSubscribePolicy::Count(1));
        let _ = self
            .tx
            .send(InMessage::SendPacketAndSubscribe(packet, subscription))
            .await;
        let res = Self::receive_packet(&mut rx, Duration::from_millis(1000)).await?;
        Ok(res)
    }

    pub fn pn532(&'_ mut self) -> Pn532<'_, Self> {
        Pn532::new(self)
    }

    pub async fn get_firmware_timestamp(&mut self) -> HinataResult<u32> {
        if self.info.firmware_timestamp > 0 {
            return Ok(self.info.firmware_timestamp);
        }
        let raw = self.request(1, &[]).await?;
        let str = String::from_utf8(raw[..10].to_vec())?;
        let num = str.parse::<u32>()?;
        self.info.firmware_timestamp = num;
        Ok(num)
    }

    pub async fn set_led(&mut self, r: u8, g: u8, b: u8) {
        self.request_without_response(0x07, &[r, g, b]).await;
    }

    pub async fn reset_led(&mut self) {
        self.request_without_response(0xEA, &[]).await
    }

    pub async fn enter_bootloader(&mut self) {
        self.request_without_response(0xF0, &[]).await
    }

    pub async fn get_chip_id(&mut self) -> HinataResult<[u8; 4]> {
        let timestamp = self.get_firmware_timestamp().await?;
        if timestamp < 2025051301 {
            return Err(Error::FirmwareTooOld);
        };
        let chip_id = if let Some(id) = self.info.chip_id {
            id
        } else {
            let res = self.request(0xE6, &[]).await?;
            let array = Self::get_four_bytes(&res[1..])?;
            self.info.chip_id = Some(array);
            array
        };
        Ok(chip_id)
    }

    fn get_four_bytes(data: &[u8]) -> HinataResult<[u8; 4]> {
        let array: [u8; 4] = data
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(Error::Protocol(ProtocolError::BufferSizeError))?;
        Ok(array)
    }

    pub async fn get_firmware_commit_hash(&mut self) -> HinataResult<[u8; 4]> {
        let timestamp = self.get_firmware_timestamp().await?;
        if timestamp < 2025051301 {
            return Err(Error::FirmwareTooOld);
        };
        let commit_hash = if let Some(hash) = self.info.firmware_commit_hash {
            hash
        } else {
            let res = self.request(0xE5, &[]).await?;
            let array = Self::get_four_bytes(&res[1..])?;
            self.info.firmware_commit_hash = Some(array);
            array
        };
        Ok(commit_hash)
    }

    pub fn get_device_name(&self) -> String {
        self.info.device_name.clone()
    }

    pub fn get_product_id(&self) -> u16 {
        self.info.pid
    }

    pub fn get_path_read(&self) -> String {
        self.info.path.read.to_string()
    }

    pub fn get_path_write(&self) -> String {
        self.info.path.write.to_string()
    }

    #[cfg(target_os = "windows")]
    pub fn get_com_instance_id(&self) -> String {
        self.info.path.com.clone().unwrap_or_default()
    }

    #[cfg(target_os = "windows")]
    pub fn get_com_port(&self) -> HinataResult<String> {
        crate::utils::com::get_com_port_by_com_instance_id(&self.get_com_instance_id())
    }
}
