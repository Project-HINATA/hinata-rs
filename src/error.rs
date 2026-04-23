use hidapi::HidError;
use thiserror::Error;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Platform error: {0}")]
    Platform(#[from] PlatformError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("PN532 hardware error: {0}")]
    Pn532(#[from] Pn532Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Disconnected: {0}")]
    Disconnected(String),

    #[error("Not Supported: {0}")]
    NotSupport(String),

    #[error("Firmware version too old")]
    FirmwareTooOld,

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("HID API error: {0}")]
    Hid(#[from] HidError),

    #[error("Win32 error: 0x{0:08X}")]
    Win32(u32),

    #[error("Serial device not found")]
    SerialDeviceNotFound,

    #[error("Device not found: {0}")]
    NotFound(String),
}

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Packet too short")]
    PacketTooShort,

    #[error("Invalid preamble")]
    InvalidPreamble,

    #[error("Invalid length checksum (LCS)")]
    InvalidLcs,

    #[error("Packet truncated")]
    PacketTruncated,

    #[error("Invalid checksum (DCS): sum=0x{sum:02X}, expected=0x{expected:02X}")]
    InvalidDcs { sum: u8, expected: u8 },

    #[error("Invalid command: 0x{0:02X}")]
    InvalidCommand(u8),

    #[error("Invalid direction: 0x{0:02X}")]
    InvalidDirection(u8),

    #[error("Empty response")]
    EmptyResponse,

    #[error("Input data too short")]
    InputTooShort,

    #[error("Buffer size error")]
    BufferSizeError,

    #[error("Mifare key must be 6 bytes")]
    InvalidMifareKeyLength,

    #[error("Mifare UID must be 4 bytes")]
    InvalidMifareUidLength,

    #[error("Mifare block data must be 16 bytes")]
    InvalidMifareBlockLength,

    #[error("Invalid response length")]
    InvalidResponseLength,

    #[error("Felica IDM must be 8 bytes")]
    InvalidFelicaIdmLength,

    #[error("Encryption error: {0}")]
    Encryption(String),
}

#[derive(Debug, Error, PartialEq, Copy, Clone)]
pub enum Pn532Error {
    #[error("No error")]
    None,
    #[error("Time Out, the target has not answered")]
    Timeout,
    #[error("A CRC error has been detected by the CIU")]
    Crc,
    #[error("A Parity error has been detected by the CIU")]
    Parity,
    #[error("Erroneous Bit Count detected during anti-collision/select")]
    CollisionBitCount,
    #[error("Framing error during MIFARE operation")]
    MifareFraming,
    #[error("Abnormal bit-collision detected during bit wise anti-collision at 106 kbps")]
    CollisionBitCollision,
    #[error("Communication buffer size insufficient")]
    NoBufs,
    #[error("RF Buffer overflow has been detected by the CIU")]
    RfNoBufs,
    #[error("RF field has not been switched on in time by the counterpart")]
    ActiveTooSlow,
    #[error("RF Protocol error")]
    RfProto,
    #[error("Internal temperature sensor has detected overheating")]
    TooHot,
    #[error("Internal buffer overflow")]
    InternalNoBufs,
    #[error("Invalid parameter (range, format...)")]
    Inval,
    #[error("DEP Protocol: Unsupported command received from the initiator")]
    DepInvalidCommand,
    #[error("DEP Protocol, MIFARE or ISO/IEC14443-4: Data format mismatch")]
    DepBadData,
    #[error("MIFARE: Authentication error")]
    MifareAuth,
    #[error("Target or Initiator does not support NFC Secure")]
    NoSecure,
    #[error("I2C bus line is Busy. A TDA transaction is on going")]
    I2cBusy,
    #[error("ISO/IEC14443-3: UID Check byte is wrong")]
    UidChecksum,
    #[error("DEP Protocol: Invalid device state")]
    DepState,
    #[error("Operation not allowed in this configuration (host controller interface)")]
    HciInval,
    #[error("Command not acceptable due to the current context")]
    Context,
    #[error("The PN532 configured as target has been released by its initiator")]
    Released,
    #[error("ISO/IEC14443-3B: Card ID does not match (card swapped)")]
    CardSwapped,
    #[error("ISO/IEC14443-3B: The card previously activated has disappeared")]
    NoCard,
    #[error("Mismatch between the NFCID3 initiator and target in DEP 212/424 kbps passive")]
    Mismatch,
    #[error("An over-current event has been detected")]
    Overcurrent,
    #[error("NAD missing in DEP frame")]
    NoNad,
    
    #[error("Unknown PN532 error: 0x{0:02X}")]
    Unknown(u8),
}

impl Pn532Error {
    pub fn from_u8(n: u8) -> Self {
        match n {
            0x00 => Pn532Error::None,
            0x01 => Pn532Error::Timeout,
            0x02 => Pn532Error::Crc,
            0x03 => Pn532Error::Parity,
            0x04 => Pn532Error::CollisionBitCount,
            0x05 => Pn532Error::MifareFraming,
            0x06 => Pn532Error::CollisionBitCollision,
            0x07 => Pn532Error::NoBufs,
            0x09 => Pn532Error::RfNoBufs,
            0x0A => Pn532Error::ActiveTooSlow,
            0x0B => Pn532Error::RfProto,
            0x0D => Pn532Error::TooHot,
            0x0E => Pn532Error::InternalNoBufs,
            0x10 => Pn532Error::Inval,
            0x12 => Pn532Error::DepInvalidCommand,
            0x13 => Pn532Error::DepBadData,
            0x14 => Pn532Error::MifareAuth,
            0x18 => Pn532Error::NoSecure,
            0x19 => Pn532Error::I2cBusy,
            0x23 => Pn532Error::UidChecksum,
            0x25 => Pn532Error::DepState,
            0x26 => Pn532Error::HciInval,
            0x27 => Pn532Error::Context,
            0x29 => Pn532Error::Released,
            0x2A => Pn532Error::CardSwapped,
            0x2B => Pn532Error::NoCard,
            0x2C => Pn532Error::Mismatch,
            0x2D => Pn532Error::Overcurrent,
            0x2E => Pn532Error::NoNad,
            _ => Pn532Error::Unknown(n),
        }
    }
}

pub type HinataResult<T> = Result<T, Error>;

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

impl From<HidError> for Error {
    fn from(e: HidError) -> Self {
        Error::Platform(PlatformError::Hid(e))
    }
}
