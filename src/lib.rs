mod message;
pub mod builder;
pub mod device;
pub mod card;
pub mod pn532;
pub mod error;
pub mod utils;
mod types;

use tokio::task::spawn_blocking;
use error::Error;
use crate::builder::{find_devices_inner, HinataDeviceBuilder};
use crate::error::HinataResult;

pub async fn find_devices(exclude: Vec<String>) -> HinataResult<Vec<HinataDeviceBuilder>> {
    let res = spawn_blocking(|| find_devices_inner(exclude)).await
        .map_err(|e| Error::Other(e.to_string()))?;
    res.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use crate::find_devices;
    #[tokio::test]
    async fn pair_device() {
        let builders = find_devices(vec![]).await.unwrap();
        let mut devices = Vec::new();
        for builder in builders {
            devices.push(builder.build(false))
        }

        println!("{:?}", devices);
    }

    #[tokio::test]
    async fn pair_device_no_panic() {
        if let Ok(builders) = find_devices(vec![]).await {

            let mut devices = Vec::new();

            for builder in builders {
                let Ok(dev) = builder.build(false) else {
                    continue
                };
                devices.push(dev)
            }

            if let Some(device) = devices.get_mut(0) {
                println!("{:?}", device.get_firmware_timestamp().await);
                println!("{:?}", device.pn532().in_list_passive_target(0, 1, &[]).await);
            }
        }
    }
}
