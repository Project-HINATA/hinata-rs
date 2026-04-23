use crate::device::{Config, HinataDevice, Info};
use crate::error::{Error, HinataResult, PlatformError};
use crate::message::{InMessage, OutMessage, Subscription};
use crate::types::HidDevicePath;
use crate::utils::device_parse::parse_hid_path;
use hidapi::{HidApi, HidDevice, HidError};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::CString;
use std::sync::OnceLock;
use std::thread;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

const HINATA_VID: u16 = 0xF822;
const USAGE_PAGE_READ: u16 = 1;
const USAGE_PAGE_WRITE: u16 = 0x06;

#[derive(Debug)]
enum HidConnectionBuilder {
    Single {
        inner: CString,
        path: String,
    },
    Dual {
        read: CString,
        write: CString,
        read_path: String,
        write_path: String,
    },
}

impl HidConnectionBuilder {
    #[cfg(target_os = "macos")]
    fn build(&self) -> Result<HidConnection, HidError> {
        let api = HidApi::new()?;
        match self {
            Self::Single { inner, .. } => Ok(HidConnection::Single(api.open_path(inner)?)),
            _ => Err(HidError::HidApiError {
                message: "Invalid connection builder for macOS".into(),
            }),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn build(&self) -> Result<HidConnection, HidError> {
        let api = HidApi::new()?;
        match self {
            Self::Dual { read, write, .. } => Ok(HidConnection::Dual {
                read: api.open_path(read)?,
                write: api.open_path(write)?,
            }),
            _ => Err(HidError::HidApiError {
                message: "Invalid connection builder for this OS".into(),
            }),
        }
    }
}

#[derive(Debug)]
enum HidConnection {
    Single(HidDevice),
    Dual { read: HidDevice, write: HidDevice },
}

impl HidConnection {
    fn write(&self, data: &[u8]) -> Result<usize, HidError> {
        match self {
            Self::Single(device) => device.write(data),
            Self::Dual { write: device, .. } => device.write(data),
        }
    }

    fn read_timeout(&mut self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HidError> {
        match self {
            Self::Single(device) => device.read_timeout(buf, timeout_ms),
            Self::Dual { read: device, .. } => device.read_timeout(buf, timeout_ms),
        }
    }
}

#[derive(Debug)]
pub struct HinataDeviceBuilder {
    connection: HidConnectionBuilder,
    instance_id: String,
    device_name: String,
    pid: u16,
    com_instance_id: OnceLock<String>,
}

impl HinataDeviceBuilder {
    pub fn build(&self, debug: bool) -> HinataResult<HinataDevice> {
        let (main_to_sub_tx, main_to_sub_rx): (Sender<InMessage>, Receiver<InMessage>) =
            mpsc::channel(255);
        let conn = self.connection.build().map_err(|e| Error::Platform(PlatformError::Hid(e)))?;

        let (read, write) = match &self.connection {
            HidConnectionBuilder::Dual {
                read_path,
                write_path,
                ..
            } => (read_path.clone(), write_path.clone()),
            HidConnectionBuilder::Single { path, .. } => (path.clone(), path.clone()),
        };

        #[cfg(target_os = "windows")]
        let path = HidDevicePath {
            read,
            write,
            com: Some(self.get_com_instance_id()?),
        };
        #[cfg(not(target_os = "windows"))]
        let path = HidDevicePath {
            read,
            write,
            com: None,
        };

        let handler = thread::spawn(move || Self::io_loop(conn, main_to_sub_rx, debug));

        let info = Info {
            firmware_timestamp: 0,
            firmware_commit_hash: None,
            chip_id: None,
            instance_id: self.instance_id.clone(),
            path,
            device_name: self.device_name.clone(),
            pid: self.pid,
        };

        Ok(HinataDevice::new(
            info,
            Config {
                sega_brightness: 0,
                sega_rapid_scan: false,
            },
            Some(handler),
            main_to_sub_tx,
        ))
    }

    pub fn get_instance_id(&self) -> String {
        self.instance_id.to_string()
    }

    pub fn get_device_name(&self) -> String {
        self.device_name.clone()
    }

    pub fn get_product_id(&self) -> u16 {
        self.pid
    }

    fn handle_hid_error(subscribes: &mut HashMap<u8, Subscription>, _: HidError) {
        subscribes.drain().for_each(|(_, channel)| {
            let _ = channel.send_no_check(OutMessage::DeviceDisconnect);
        });
    }
    fn io_loop(mut connection: HidConnection, mut message_in: Receiver<InMessage>, debug: bool) {
        let mut buf = [0; 64];
        let mut subscribes: HashMap<u8, Subscription> = HashMap::new();

        loop {
            loop {
                match message_in.try_recv() {
                    Ok(mes) => {
                        let mut data_to_write = None;

                        match mes {
                            InMessage::SendPacket(data) => {
                                data_to_write = Some(data);
                            }
                            InMessage::SendPacketAndSubscribe(data, subscription) => {
                                let key = if data[1] == 1 { 50 } else { data[1] };
                                subscribes.insert(key, subscription);
                                data_to_write = Some(data);
                            }
                            InMessage::Subscribe(cmd, subscription) => {
                                subscribes.insert(cmd, subscription);
                            }
                            InMessage::UnSubscribe(cmd) => {
                                subscribes.remove(&cmd);
                            }
                        }

                        if let Some(data) = data_to_write {
                            match connection.write(&data) {
                                Ok(_) => {
                                    if debug {
                                        println!("DEBUG: -> {:02X?}", data)
                                    }
                                }
                                Err(e) => Self::handle_hid_error(&mut subscribes, e),
                            }
                        }
                    }
                    Err(e) => match e {
                        mpsc::error::TryRecvError::Empty => break, // 没消息了，去读 HID
                        mpsc::error::TryRecvError::Disconnected => return, // 主线程断开，退出
                    },
                }
            }

            match connection.read_timeout(&mut buf, 16) {
                Ok(len) => {
                    if len > 0 {
                        if let Entry::Occupied(mut entry) = subscribes.entry(buf[1]) {
                            if entry
                                .get_mut()
                                .send(OutMessage::Response(buf[1..].to_vec()))
                            {
                                entry.remove();
                            }
                        }
                        if debug {
                            println!("DEBUG: <- {:02X?}", &buf[..len])
                        }
                    }
                }
                Err(e) => Self::handle_hid_error(&mut subscribes, e),
            }
        }
    }

    // == Windows specific COM ==

    #[cfg(target_os = "windows")]
    pub fn get_com_port(&mut self) -> HinataResult<String> {
        let instance_id = self.get_com_instance_id()?;
        crate::utils::com::get_com_port_by_com_instance_id(&instance_id)
    }

    #[cfg(target_os = "windows")]
    pub fn get_com_instance_id(&self) -> HinataResult<String> {
        if let Some(id) = self.com_instance_id.get() {
            return Ok(id.clone());
        }

        let path_read = match &self.connection {
            HidConnectionBuilder::Dual { read_path, .. } => read_path,
            HidConnectionBuilder::Single { path, .. } => path,
        };

        let instance_id = crate::utils::com::get_com_instance_id_by_hid_instance_id(path_read)?;
        let _ = self.com_instance_id.set(instance_id.clone());
        Ok(instance_id)
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn find_devices_inner(
    exclude: Vec<String>,
) -> Result<Vec<HinataDeviceBuilder>, HidError> {
    struct PreDeviceBuilder {
        read: Option<(CString, String)>,
        write: Option<(CString, String)>,
        device_name: Option<String>,
        pid: Option<u16>,
    }

    let mut hid = HidApi::new()?;
    hid.add_devices(HINATA_VID, 0)?;

    let mut devices: HashMap<String, PreDeviceBuilder> = HashMap::new();

    for device in hid.device_list() {
        if device.vendor_id() != HINATA_VID {
            continue;
        }

        if let Some((path, instance)) = parse_hid_path(&device.path().to_string_lossy()) {
            if exclude.contains(&instance) {
                continue;
            };
            let entry = devices.entry(instance).or_insert(PreDeviceBuilder {
                read: None,
                write: None,
                device_name: device.product_string().map(|s| s.to_string()),
                pid: Some(device.product_id()),
            });

            if device.usage_page() == USAGE_PAGE_READ {
                entry.read = Some((device.path().to_owned(), path));
            } else if device.usage_page() == USAGE_PAGE_WRITE {
                entry.write = Some((device.path().to_owned(), path));
            }
        }
    }

    Ok(devices
        .into_iter()
        .filter_map(|(instance, builder)| {
            if let PreDeviceBuilder {
                read: Some((read_raw, read)),
                write: Some((write_raw, write)),
                device_name: Some(n),
                pid: Some(p),
            } = builder
            {
                Some(HinataDeviceBuilder {
                    connection: HidConnectionBuilder::Dual {
                        read: read_raw,
                        write: write_raw,
                        read_path: read,
                        write_path: write,
                    },
                    instance_id: instance,
                    device_name: n,
                    pid: p,
                    com_instance_id: OnceLock::new(),
                })
            } else {
                None
            }
        })
        .collect())
}

#[cfg(target_os = "macos")]
pub(crate) fn find_devices_inner(
    exclude: Vec<String>,
) -> Result<Vec<HinataDeviceBuilder>, HidError> {
    let mut hid = HidApi::new()?;
    hid.add_devices(HINATA_VID, 0)?;

    let mut devices = Vec::new();

    for device in hid.device_list() {
        if device.vendor_id() == HINATA_VID && device.usage_page() == USAGE_PAGE_WRITE {
            if let (Some((instance, _)), Some(name)) = (
                parse_hid_path(&device.path().to_string_lossy()),
                device.product_string(),
            ) {
                if exclude.contains(&instance) {
                    continue;
                };
                devices.push(HinataDeviceBuilder {
                    connection: HidConnectionBuilder::Single {
                        inner: device.path().to_owned(),
                        path: instance.clone(),
                    }, // 使用统一封装
                    instance_id: instance.clone(),
                    device_name: name.to_string(),
                    pid: device.product_id(),
                    com_instance_id: OnceLock::new(),
                });
            };
        }
    }
    Ok(devices)
}

#[test]
fn test_hid_init() {
    let start = std::time::Instant::now();
    let mut hid = HidApi::new().unwrap();
    hid.add_devices(HINATA_VID, 0).unwrap();
    let duration = start.elapsed();
    println!("Time elapsed: {:?}", duration);
}

#[test]
fn test_hid_all_init() {
    let start = std::time::Instant::now();
    let mut hid = HidApi::new().unwrap();
    hid.add_devices(0, 0).unwrap();
    let duration = start.elapsed();
    println!("Time elapsed: {:?}", duration);
}
