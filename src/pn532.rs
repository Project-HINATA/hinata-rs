use std::io::{Cursor, Read};
use async_trait::async_trait;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use crate::card::{Felica, Iso14443a, PassiveTarget};
use crate::error::{Error, HinataResult, ProtocolError, Pn532Error};
use byteorder::{BigEndian, ReadBytesExt};

pub const HINATA_STANDARD_PRODUCT_ID: u16 = 0x0147;
pub const HINATA_LITE_PRODUCT_ID: u16 = 0x0148;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeARfProfile {
    pub rf_cfg: u8,
    pub cw_gs_n_on: u8,
    pub cw_gs_p: u8,
}

pub const PN532_DEFAULT_TYPE_A_RF_PROFILE: TypeARfProfile = TypeARfProfile {
    rf_cfg: 0x59,
    cw_gs_n_on: 0x0F,
    cw_gs_p: 0x3F,
};

pub const HINATA_STANDARD_TYPE_A_RF_PROFILES: [TypeARfProfile; 2] = [
    PN532_DEFAULT_TYPE_A_RF_PROFILE,
    TypeARfProfile {
        rf_cfg: 0x69,
        cw_gs_n_on: 0x0F,
        cw_gs_p: 0x2B,
    },
];

pub const HINATA_LITE_TYPE_A_RF_PROFILES: [TypeARfProfile; 3] = [
    TypeARfProfile {
        rf_cfg: 0x29,
        cw_gs_n_on: 0x03,
        cw_gs_p: 0x11,
    },
    TypeARfProfile {
        rf_cfg: 0x49,
        cw_gs_n_on: 0x0B,
        cw_gs_p: 0x0C,
    },
    PN532_DEFAULT_TYPE_A_RF_PROFILE,
];

pub fn type_a_rf_profiles_for_product_id(product_id: u16) -> &'static [TypeARfProfile] {
    match product_id {
        HINATA_STANDARD_PRODUCT_ID => &HINATA_STANDARD_TYPE_A_RF_PROFILES,
        HINATA_LITE_PRODUCT_ID => &HINATA_LITE_TYPE_A_RF_PROFILES,
        _ => std::slice::from_ref(&PN532_DEFAULT_TYPE_A_RF_PROFILE),
    }
}

#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Pn532Direction {
    HostToPn532 = 0xD4,
    Pn532ToHost = 0xD5,
}
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Pn532Command {
    Diagnose = 0x00,
    GetFirmwareVersion = 0x02,
    GetGeneralStatus = 0x04,
    ReadRegister = 0x06,
    WriteRegister = 0x08,
    ReadGpio = 0x0C,
    WriteGpio = 0x0E,
    SetSerialBaudRate = 0x10,
    SetParameters = 0x12,
    SamConfiguration = 0x14,
    PowerDown = 0x16,
    RfConfiguration = 0x32,
    RfRegulationTest = 0x58,
    InJumpForDep = 0x56,
    InJumpForPsl = 0x46,
    InListPassiveTarget = 0x4A,
    InAtr = 0x50,
    InPsl = 0x4E,
    InDataExchange = 0x40,
    InCommunicateThru = 0x42,
    InDeselect = 0x44,
    InRelease = 0x52,
    InSelect = 0x54,
    InAutoPoll = 0x60,
    TgInitAsTarget = 0x8C,
    TgSetGeneralBytes = 0x92,
    TgGetData = 0x86,
    TgSetData = 0x8E,
    TgSetMetadata = 0x94,
    TgGetInitiatorCommand = 0x88,
    TgResponseToInitiator = 0x90,
    TgGetTargetStatus = 0x8A,
}

pub enum Pn532ApplicationError {}

#[derive(FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum MifareCommand {
    AuthA = 0x60,
    AuthB = 0x61,
    Read = 0x30,
    Write = 0xA0,
    Transfer = 0xB0,
    Decrement = 0xC0,
    Increment = 0xC1,
    Store = 0xC2,
    /// Specific to Mifare Ultralight cards
    UltralightWrite = 0xA2,
}
#[derive(FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum FelicaCommand {
    Polling = 0x00,
    RequestService = 0x02,
    RequestResponse = 0x04,
    ReadWithoutEncryption = 0x06,
    WriteWithoutEncryption = 0x08,
    RequestSystemCode = 0x0C,
}

#[derive(Debug)]
pub struct Pn532Packet {
    pub direction: Pn532Direction,
    pub command: Pn532Command,
    pub payload: Vec<u8>,
}

impl Pn532Packet {
    pub fn new(direction: Pn532Direction, command: Pn532Command, payload: Vec<u8>) -> Self {
        Self {
            direction,
            command,
            payload,
        }
    }

    pub fn from_bytes(data: &[u8]) -> HinataResult<Self> {
        if data.len() < 9 {
            return Err(Error::Protocol(ProtocolError::PacketTooShort));
        }

        if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0xFF {
            return Err(Error::Protocol(ProtocolError::InvalidPreamble));
        }

        let payload_len = data[3];
        let lcs = data[4];
        if payload_len.wrapping_add(lcs) != 0 {
            return Err(Error::Protocol(ProtocolError::InvalidLcs));
        }

        let direction_byte = data[5];
        let direction = Pn532Direction::from_u8(direction_byte).ok_or(Error::Protocol(ProtocolError::InvalidDirection(direction_byte)))?;

        let cmd_byte = data[6];
        let cmd = Pn532Command::from_u8(match direction {
            Pn532Direction::HostToPn532 => cmd_byte,
            Pn532Direction::Pn532ToHost => cmd_byte - 1
        }).ok_or(Error::Protocol(ProtocolError::InvalidCommand(cmd_byte)))?;

        let dcs_index = 5 + payload_len as usize;
        if data.len() <= dcs_index {
            return Err(Error::Protocol(ProtocolError::PacketTruncated));
        }

        let mut checksum_sum: u8 = 0;
        for i in 5..dcs_index {
            checksum_sum = checksum_sum.wrapping_add(data[i]);
        }

        let expected_dcs = data[dcs_index];
        if checksum_sum.wrapping_add(expected_dcs) != 0 {
            return Err(Error::Protocol(ProtocolError::InvalidDcs { sum: checksum_sum, expected: expected_dcs }));
        }

        let payload = data[7..dcs_index].to_vec();

        Ok(Pn532Packet {
            direction,
            command: cmd,
            payload,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let len = (self.payload.len() + 2) as u8;
        let lcs = (!len).wrapping_add(1);

        buffer.extend_from_slice(&[0x00, 0x00, 0xFF]);
        buffer.push(len);
        buffer.push(lcs);

        let tfi = self.direction as u8;
        let cmd = match self.direction {
            Pn532Direction::HostToPn532 => self.command as u8,
            Pn532Direction::Pn532ToHost => self.command as u8 + 1
        };
        buffer.push(tfi);
        buffer.push(cmd);
        buffer.extend_from_slice(&self.payload);

        let mut dcs_sum: u8 = tfi.wrapping_add(cmd);
        for &byte in &self.payload {
            dcs_sum = dcs_sum.wrapping_add(byte);
        }
        let dcs = (!dcs_sum).wrapping_add(1);

        buffer.push(dcs);
        buffer.push(0x00); // Postamble

        buffer
    }
}

#[async_trait]
pub trait Pn532Port {
    async fn request(&mut self, pn532_cmd: Pn532Command, payload: &[u8]) -> HinataResult<Vec<u8>>;
}

pub struct Pn532<'a, P: Pn532Port> {
    port: &'a mut P
}

impl <'a, P: Pn532Port> Pn532<'a, P> {
    pub fn new(port: &'a mut P) -> Self {
        Self {
            port
        }
    }

    pub async fn in_list_passive_target(&mut self, brty: u8, max_tg: u8, initial_data: &[u8]) -> HinataResult<Vec<PassiveTarget>> {
        let mut payload = vec![max_tg, brty];
        payload.extend_from_slice(initial_data);
        let res = self.port.request(Pn532Command::InListPassiveTarget, &payload).await?;
        parse_in_list_passive_target(&res, brty)
    }


    fn get_error_code(data: &[u8]) -> HinataResult<()> {
        let status_byte = data.get(0).ok_or(Error::Protocol(ProtocolError::EmptyResponse))?;
        let error = Pn532Error::from_u8(*status_byte);
        if error == Pn532Error::None {
            Ok(())
        } else {
            Err(Error::Pn532(error))
        }
    }

    fn ensure_response(data: &[u8]) -> HinataResult<()> {
        data.first()
            .map(|_| ())
            .ok_or(Error::Protocol(ProtocolError::EmptyResponse))
    }

    pub async fn in_data_exchange(&mut self, tg: u8, cmd: u8, data: &[u8]) -> HinataResult<Vec<u8>> {
        let mut payload = vec![tg, cmd];
        payload.extend_from_slice(data);
        let res = self.port.request(Pn532Command::InDataExchange, &payload).await?;
        Self::get_error_code(&res)?;
        Ok(res)
    }

    pub async fn mifare_classic_auth(&mut self, tg: u8, uid: &[u8], block_num: u8, key_num: MifareCommand, key: &[u8]) -> HinataResult<()> {
        let mut input = vec![block_num];
        input.extend_from_slice(key.get(..6).ok_or(Error::Protocol(ProtocolError::InvalidMifareKeyLength))?);
        input.extend_from_slice(uid.get(..4).ok_or(Error::Protocol(ProtocolError::InvalidMifareUidLength))?);
        self.in_data_exchange(tg, key_num as u8, &input).await?;
        Ok(())
    }

    pub async fn mifare_classic_write_block(&mut self, tg: u8, block_num: u8, data: &[u8]) -> HinataResult<()> {
        let mut input = vec![block_num];
        input.extend_from_slice(data.get(..16).ok_or(Error::Protocol(ProtocolError::InvalidMifareBlockLength))?);
        self.in_data_exchange(tg, MifareCommand::Write as u8, &input).await?;
        Ok(())
    }

    pub async fn mifare_classic_read_block(&mut self, tg: u8, block_num: u8) -> HinataResult<[u8; 16]>{
        let input = [block_num];
        let res = self.in_data_exchange(tg, MifareCommand::Read as u8, &input).await?;

        let block_data = res.get(1..17).ok_or(Error::Protocol(ProtocolError::InvalidResponseLength))?;
        let mut block = [0u8; 16];
        block.copy_from_slice(block_data);
        Ok(block)

    }

    pub async fn in_release(&mut self, tg: u8) -> HinataResult<()> {
        let res = self.port.request(Pn532Command::InRelease, &[tg]).await?;
        Self::ensure_response(&res)
    }

    pub async fn in_deselect(&mut self, tg: u8) -> HinataResult<()> {
        let res = self.port.request(Pn532Command::InDeselect, &[tg]).await?;
        Self::ensure_response(&res)
    }

    pub async fn in_select(&mut self, tg: u8) -> HinataResult<()> {
        let res = self.port.request(Pn532Command::InSelect, &[tg]).await?;
        Self::get_error_code(&res)
    }

    pub async fn set_type_a_rf_profile(&mut self, profile: TypeARfProfile) -> HinataResult<()> {
        if profile.cw_gs_n_on > 0x0F {
            return Err(Error::Protocol(ProtocolError::InvalidTypeACwGsNOn(
                profile.cw_gs_n_on,
            )));
        }
        if profile.cw_gs_p > 0x3F {
            return Err(Error::Protocol(ProtocolError::InvalidTypeACwGsP(
                profile.cw_gs_p,
            )));
        }

        let gs_n_on = (profile.cw_gs_n_on << 4) | 0x04;
        let payload = [
            0x0A,
            profile.rf_cfg,
            gs_n_on,
            profile.cw_gs_p,
            0x11,
            0x4D,
            0x85,
            0x61,
            0x6F,
            0x26,
            0x62,
            0x87,
        ];
        self.port
            .request(Pn532Command::RfConfiguration, &payload)
            .await?;
        Ok(())
    }

    pub async fn set_type_a_rf_power(&mut self, cw_gs_n_on: u8, cw_gs_p: u8) -> HinataResult<()> {
        self.set_type_a_rf_profile(TypeARfProfile {
            rf_cfg: PN532_DEFAULT_TYPE_A_RF_PROFILE.rf_cfg,
            cw_gs_n_on,
            cw_gs_p,
        })
        .await
    }

    pub async fn felica_read_without_encryption(&mut self, tg: u8, idm: &[u8], services: &[u16], blocks: &[u16]) -> HinataResult<Vec<u8>> {
        let mut input = vec![FelicaCommand::ReadWithoutEncryption as u8];
        input.extend_from_slice(idm.get(..8).ok_or(Error::Protocol(ProtocolError::InvalidFelicaIdmLength))?);
        input.push(services.len() as u8);
        for &service in services {
            input.extend_from_slice(&service.to_be_bytes());
        }
        input.push(blocks.len() as u8);
        for &block in blocks {
            input.extend_from_slice(&block.to_be_bytes());
        }

        let length = (input.len() + 1) as u8;
        self.in_data_exchange(tg, length, &input).await
    }
}

fn parse_in_list_passive_target(data: &[u8], brty: u8) -> HinataResult<Vec<PassiveTarget>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut cursor = Cursor::new(data);

    let tag_num = cursor.read_u8()?;
    let mut tags = Vec::with_capacity(tag_num as usize);

    for _ in 0..tag_num {
        let _tg = cursor.read_u8()?; // 跳过 Tg

        match brty {
            0 => { // Type A
                let atqa = cursor.read_u16::<BigEndian>()?;
                let sak  = cursor.read_u8()?;
                let len  = cursor.read_u8()? as usize;

                let mut uid = vec![0u8; len];
                cursor.read_exact(&mut uid)?;

                tags.push(PassiveTarget::Iso14443a(Iso14443a::new(uid, sak, atqa)));
            },
            1 | 2 => { // FeliCa
                let len = cursor.read_u8()? as usize;
                if len < 18 { return Err(Error::Protocol(ProtocolError::InvalidResponseLength)); }

                let _code = cursor.read_u8()?; // 跳过 code

                let mut idm = [0u8; 8];
                cursor.read_exact(&mut idm)?;

                let mut pmm = [0u8; 8];
                cursor.read_exact(&mut pmm)?;

                let sys_cnt = (len - 18) / 2;
                let mut sys_codes = Vec::with_capacity(sys_cnt);
                for _ in 0..sys_cnt {
                    sys_codes.push(cursor.read_u16::<BigEndian>()?);
                }

                tags.push(PassiveTarget::Felica(Felica::new(idm, pmm, sys_codes)));
            }
            _ => return Err(Error::NotSupport("Unsupported brty".into())),
        }
    }
    Ok(tags)
}
pub fn gen_felica_poll_initial_data(system_code: u16, request_code: u16) -> Vec<u8> {
    vec![
        FelicaCommand::Polling as u8,
        (system_code >> 8) as u8,
        (system_code & 0xFF) as u8,
        (request_code & 0xFF) as u8,
        0
    ]
}

#[test]
fn packet_test() {
    let example = vec![0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00];
    let example2 = vec![0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD5, 0x4B, 0x00, 0xE0, 0x00];
    let packet = Pn532Packet::from_bytes(&example).unwrap();
    let packet2 = Pn532Packet::from_bytes(&example2).unwrap();
    println!("{:?}", packet2);
    println!("{:02X?}", packet.to_bytes());
    println!("{:02X?}", packet2.to_bytes());

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_in_list_response_is_no_targets() {
        assert_eq!(
            parse_in_list_passive_target(&[], 0).unwrap(),
            Vec::<PassiveTarget>::new()
        );
    }

    #[derive(Default)]
    struct RecordingPort {
        requests: Vec<(Pn532Command, Vec<u8>)>,
        response: Vec<u8>,
    }

    #[async_trait]
    impl Pn532Port for RecordingPort {
        async fn request(
            &mut self,
            command: Pn532Command,
            payload: &[u8],
        ) -> HinataResult<Vec<u8>> {
            self.requests.push((command, payload.to_vec()));
            Ok(self.response.clone())
        }
    }

    struct FailingPort;

    #[async_trait]
    impl Pn532Port for FailingPort {
        async fn request(
            &mut self,
            _command: Pn532Command,
            _payload: &[u8],
        ) -> HinataResult<Vec<u8>> {
            Err(Error::Timeout("scripted cleanup timeout".into()))
        }
    }

    #[tokio::test]
    async fn in_deselect_sends_target_action_command() {
        let mut port = RecordingPort {
            response: vec![0],
            ..Default::default()
        };

        Pn532::new(&mut port).in_deselect(3).await.unwrap();

        assert_eq!(port.requests, vec![(Pn532Command::InDeselect, vec![3])]);
    }

    #[tokio::test]
    async fn target_cleanup_ignores_unknown_target_status() {
        let mut release_port = RecordingPort {
            response: vec![0x27],
            ..Default::default()
        };
        let mut deselect_port = RecordingPort {
            response: vec![0x27],
            ..Default::default()
        };

        Pn532::new(&mut release_port).in_release(1).await.unwrap();
        Pn532::new(&mut deselect_port).in_deselect(1).await.unwrap();
    }

    #[tokio::test]
    async fn target_cleanup_rejects_empty_response() {
        let mut port = RecordingPort::default();

        let result = Pn532::new(&mut port).in_release(1).await;

        assert!(matches!(
            result,
            Err(Error::Protocol(ProtocolError::EmptyResponse))
        ));
    }

    #[tokio::test]
    async fn target_cleanup_preserves_transport_errors() {
        let result = Pn532::new(&mut FailingPort).in_release(1).await;

        assert!(matches!(result, Err(Error::Timeout(_))));
    }

    #[tokio::test]
    async fn set_type_a_rf_power_sends_complete_analog_settings() {
        let mut port = RecordingPort::default();

        Pn532::new(&mut port)
            .set_type_a_rf_power(0x0C, 0x28)
            .await
            .unwrap();

        assert_eq!(
            port.requests,
            vec![(
                Pn532Command::RfConfiguration,
                vec![
                    0x0A, 0x59, 0xC4, 0x28, 0x11, 0x4D, 0x85, 0x61, 0x6F, 0x26, 0x62, 0x87,
                ],
            )],
        );
    }

    #[tokio::test]
    async fn set_type_a_rf_profile_uses_the_selected_receiver_gain() {
        let mut port = RecordingPort::default();

        Pn532::new(&mut port)
            .set_type_a_rf_profile(HINATA_STANDARD_TYPE_A_RF_PROFILES[1])
            .await
            .unwrap();

        assert_eq!(
            port.requests,
            vec![(
                Pn532Command::RfConfiguration,
                vec![
                    0x0A, 0x69, 0xF4, 0x2B, 0x11, 0x4D, 0x85, 0x61, 0x6F, 0x26, 0x62, 0x87,
                ],
            )],
        );
    }

    #[test]
    fn type_a_rf_profiles_are_bound_to_the_reader_product() {
        assert_eq!(
            type_a_rf_profiles_for_product_id(HINATA_STANDARD_PRODUCT_ID),
            HINATA_STANDARD_TYPE_A_RF_PROFILES,
        );
        assert_eq!(
            type_a_rf_profiles_for_product_id(HINATA_LITE_PRODUCT_ID),
            HINATA_LITE_TYPE_A_RF_PROFILES,
        );
        assert_eq!(
            type_a_rf_profiles_for_product_id(0),
            [PN532_DEFAULT_TYPE_A_RF_PROFILE],
        );
    }

    #[tokio::test]
    async fn set_type_a_rf_power_rejects_values_outside_register_ranges() {
        let mut port = RecordingPort::default();

        assert!(
            Pn532::new(&mut port)
                .set_type_a_rf_power(0x10, 0x28)
                .await
                .is_err()
        );
        assert!(
            Pn532::new(&mut port)
                .set_type_a_rf_power(0x0C, 0x40)
                .await
                .is_err()
        );
        assert!(port.requests.is_empty());
    }
}
