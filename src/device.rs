use ocl::{Platform as ClPlatform, Device as ClDevice};
use anyhow::anyhow;

pub struct Device {
    pub platform: ClPlatform,
    pub device: ClDevice,
}

impl Device {
    pub fn list_all() -> anyhow::Result<Vec<Self>> {
        let mut res = Vec::new();
        for platform in ClPlatform::list() {
            let devices = ClDevice::list_all(platform)
                .map_err(|e| anyhow!(e))?;
            for device in devices {
                res.push(Self { platform, device });
            }
        }
        Ok(res)
    }

    pub fn name(&self) -> anyhow::Result<String> {
        self.device.name().map_err(|e| anyhow!(e))
    }
}
