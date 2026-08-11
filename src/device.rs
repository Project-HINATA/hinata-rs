use crate::error::{Error, HinataResult, ProtocolError};
use crate::message::{InMessage, OutMessage, Subscription, UnSubscribePolicy};
use crate::pn532::{Pn532, Pn532Command, Pn532Direction, Pn532Packet, Pn532Port};
use crate::types::HidDevicePath;
use async_trait::async_trait;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

const PN532_RESPONSE_HEADER: u8 = 0xE2;
const PN532_FRAME_TIMEOUT: Duration = Duration::from_millis(1000);

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn test_device(tx: Sender<InMessage>) -> HinataDevice {
        HinataDevice::new(
            Info {
                firmware_timestamp: 0,
                firmware_commit_hash: None,
                chip_id: None,
                instance_id: "test".to_string(),
                path: HidDevicePath {
                    read: "test-read".to_string(),
                    write: "test-write".to_string(),
                    com: None,
                },
                device_name: "test".to_string(),
                pid: 0,
            },
            Config {
                sega_brightness: 0,
                sega_rapid_scan: false,
            },
            None,
            tx,
        )
    }

    fn ack_frame() -> Vec<u8> {
        vec![PN532_RESPONSE_HEADER, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00]
    }

    fn response_frame(command: Pn532Command, payload: Vec<u8>) -> Vec<u8> {
        let packet = Pn532Packet::new(Pn532Direction::Pn532ToHost, command, payload);
        let mut response = vec![PN532_RESPONSE_HEADER];
        response.extend_from_slice(&packet.to_bytes());
        response
    }

    async fn take_subscription(rx: &mut Receiver<InMessage>) -> Subscription {
        match rx.recv().await.expect("request message") {
            InMessage::SendPacketAndSubscribe(_, subscription) => subscription,
            _ => panic!("expected subscribed request"),
        }
    }

    async fn send_frames(mut subscription: Subscription, frames: Vec<Vec<u8>>) {
        tokio::task::spawn_blocking(move || {
            for frame in frames {
                assert!(!subscription.send(OutMessage::Response(frame)));
            }
        })
        .await
        .expect("frame sender");
    }

    async fn expect_unsubscribe(rx: &mut Receiver<InMessage>) {
        match rx.recv().await.expect("unsubscribe message") {
            InMessage::UnSubscribe(PN532_RESPONSE_HEADER) => {}
            _ => panic!("expected PN532 unsubscribe"),
        }
    }

    #[tokio::test]
    async fn pn532_request_accepts_response_after_200_ms() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut device = test_device(tx);
        let request = tokio::spawn(async move {
            <HinataDevice as Pn532Port>::request(
                &mut device,
                Pn532Command::InListPassiveTarget,
                &[],
            )
            .await
        });

        let mut subscription = take_subscription(&mut rx).await;
        tokio::task::spawn_blocking(move || {
            assert!(!subscription.send(OutMessage::Response(ack_frame())));
            std::thread::sleep(Duration::from_millis(250));
            assert!(!subscription.send(OutMessage::Response(response_frame(
                Pn532Command::InListPassiveTarget,
                vec![0x00],
            ))));
        })
        .await
        .expect("delayed frame sender");

        assert_eq!(request.await.expect("request task").unwrap(), vec![0x00]);
        expect_unsubscribe(&mut rx).await;
    }

    #[tokio::test]
    async fn pn532_request_ignores_response_for_another_command() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut device = test_device(tx);
        let request = tokio::spawn(async move {
            <HinataDevice as Pn532Port>::request(
                &mut device,
                Pn532Command::InListPassiveTarget,
                &[],
            )
            .await
        });

        let subscription = take_subscription(&mut rx).await;
        send_frames(
            subscription,
            vec![
                ack_frame(),
                response_frame(Pn532Command::RfConfiguration, vec![0xAA]),
                response_frame(Pn532Command::InListPassiveTarget, vec![0x00]),
            ],
        )
        .await;

        assert_eq!(request.await.expect("request task").unwrap(), vec![0x00]);
        expect_unsubscribe(&mut rx).await;
    }
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
        // Keep the subscription alive until the expected command arrives. A
        // timed-out PN532 operation can otherwise deliver its final frame to
        // the next request, because every passthrough packet shares 0xE2.
        let (subscription, mut rx) = Subscription::new(UnSubscribePolicy::Never);
        let packet = Pn532Packet::new(Pn532Direction::HostToPn532, pn532_cmd, payload.to_vec());
        let mut send = vec![1, PN532_RESPONSE_HEADER];
        send.extend_from_slice(&packet.to_bytes());

        self.tx
            .send(InMessage::SendPacketAndSubscribe(send, subscription))
            .await
            .map_err(|_| Error::Disconnected("Device I/O loop disconnected".into()))?;

        let result = loop {
            // Firmware can keep a PN532 command alive for 500 ms and may then
            // wait up to another 250 ms for the HID IN endpoint. Waiting one
            // second consumes that terminal frame instead of abandoning it.
            let res = match Self::receive_packet(&mut rx, PN532_FRAME_TIMEOUT).await {
                Ok(res) => res,
                Err(e) => break Err(e),
            };
            let Some(len) = res.get(4) else {
                break Err(Error::Protocol(ProtocolError::PacketTooShort));
            };
            let Some(len_rev) = res.get(5) else {
                break Err(Error::Protocol(ProtocolError::PacketTooShort));
            };
            if *len == 0 && *len_rev == 0xFF {
                // ack
                continue;
            } else if (*len).wrapping_add(*len_rev) != 0 {
                break Err(Error::Protocol(ProtocolError::InvalidLcs));
            }
            if *len > 0 {
                let res_packet = match Pn532Packet::from_bytes(&res[1..]) {
                    Ok(packet) => packet,
                    Err(e) => break Err(e),
                };
                if res_packet.direction != Pn532Direction::Pn532ToHost
                    || res_packet.command != pn532_cmd
                {
                    continue;
                }
                break Ok(res_packet.payload);
            }
        };

        let _ = self
            .tx
            .send(InMessage::UnSubscribe(PN532_RESPONSE_HEADER))
            .await;
        result
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
