use winreg::enums::*;
use winreg::RegKey;
use windows::core::{GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
use windows::Win32::Devices::Properties::{DEVPKEY_Device_ClassGuid, DEVPROPTYPE, DEVPROP_TYPE_GUID};
use crate::error::{Error, HinataResult, PlatformError};

const GUID_DEVCLASS_PORTS: GUID = GUID::from_u128(0x4d36e978_e325_11ce_bfc1_08002be10318);

pub fn get_com_port_by_hid_instance(instance: &str) -> HinataResult<String> {
    let com_instance = get_com_instance_id_by_hid_instance_id(instance)?;
    get_com_port_by_com_instance_id(&com_instance)
}

pub fn get_com_instance_id_by_hid_instance_id(instance_id: &str) -> HinataResult<String> {
    unsafe {
        // 1. 准备字符串
        let input_id_wide: Vec<u16> = instance_id
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // 2. 定位起始节点 (Locate)
        let mut current_dev_node: u32 = 0;
        let ret = CM_Locate_DevNodeW(
            &mut current_dev_node,
            PCWSTR::from_raw(input_id_wide.as_ptr()),
            CM_LOCATE_DEVNODE_NORMAL,
        );

        if ret != CR_SUCCESS {
            return Err(Error::Platform(PlatformError::Win32(ret.0 as u32)));
        }

        // 3. 开始向上爬树循环 (最多爬 3-4 层足够了，防止死循环)
        // 层级关系通常是: HID Collection -> USB Interface -> USB Composite -> USB Hub
        for _depth in 0..5 {
            // A. 获取当前节点的父节点
            let mut parent_dev_node: u32 = 0;
            let ret = CM_Get_Parent(&mut parent_dev_node, current_dev_node, 0);

            if ret != CR_SUCCESS {
                // 到顶了或者出错了，停止
                break;
            }

            // B. 检查这个父节点的所有子节点（寻找 Serial Port）
            if let Some(serial_id) = find_child_port(parent_dev_node) {
                return Ok(serial_id);
            }

            // C. 没找到，继续向上爬
            current_dev_node = parent_dev_node;
        }
    }

    Err(Error::Platform(PlatformError::SerialDeviceNotFound))
}

/// 辅助函数：检查指定父节点的所有直接子节点，看有没有 Ports 类型的
unsafe fn find_child_port(parent_node: u32) -> Option<String> {
    unsafe {
        let mut child_node: u32 = 0;
        // 获取第一个子节点
        if CM_Get_Child(&mut child_node, parent_node, 0) != CR_SUCCESS {
            return None;
        }

        let mut current_node = child_node;

        // 遍历所有兄弟节点
        loop {
            // --- 检查 Class GUID ---
            let mut buffer = [0u8; 16];
            let mut buffer_size = buffer.len() as u32;
            let property_type: u32 = 0;

            let mut dev_prop_type = DEVPROPTYPE(property_type);

            // 获取 ClassGuid 属性
            let ret = CM_Get_DevNode_PropertyW(
                current_node,
                &DEVPKEY_Device_ClassGuid,
                &mut dev_prop_type,
                Some(buffer.as_mut_ptr()),
                &mut buffer_size,
                0
            );

            // 如果是 Ports 设备
            if ret == CR_SUCCESS
                && dev_prop_type == DEVPROP_TYPE_GUID
                && *(buffer.as_ptr() as *const GUID) == GUID_DEVCLASS_PORTS
            {
                // 获取它的 Instance ID
                let mut id_buffer = [0u16; 256];
                if CM_Get_Device_IDW(current_node, &mut id_buffer, 0) == CR_SUCCESS {
                    let device_id = String::from_utf16_lossy(&id_buffer);
                    return Some(device_id.trim_matches(char::from(0)).to_string());
                }
            }

            // --- 移动到下一个兄弟 ---
            let mut next_node: u32 = 0;
            if CM_Get_Sibling(&mut next_node, current_node, 0) != CR_SUCCESS {
                break; // 遍历结束
            }
            current_node = next_node;
        }

        None
    }
}

/// 辅助函数：直接从注册表读取 PortName
pub fn get_com_port_by_com_instance_id(instance_id: &str) -> HinataResult<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key_path = format!("SYSTEM\\CurrentControlSet\\Enum\\{}\\Device Parameters", instance_id);
    let key = hklm.open_subkey(&key_path)?;

    let port_name: String = key.get_value("PortName")?;

    Ok(port_name)
}

#[test]
fn get_port_test() {
    let com_serial = get_com_instance_id_by_hid_instance_id("HID\\VID_F822&PID_0147&MI_02&Col01\\8&38333037&0&0000").unwrap();
    let port = get_com_port_by_com_instance_id(&com_serial).unwrap();
    println!("{}, {}", com_serial, port);
}
