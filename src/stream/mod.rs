use std::sync::Arc;

use tun_rs::{AsyncDevice, DeviceBuilder};

pub type StreamResult<T> = std::io::Result<T>;

pub trait Stream {
    fn read(&self, buffer: &mut [u8]) -> impl Future<Output = StreamResult<usize>>;
    fn write(&self, bytes: &[u8]) -> impl Future<Output = StreamResult<()>>;
}

#[derive(Clone)]
pub struct TunStream {
    device: Arc<AsyncDevice>,
}

impl TunStream {
    pub fn new(device_name: &str) -> StreamResult<Self> {
        let device = DeviceBuilder::new()
            .name(device_name)
            .mtu(1500)
            .build_async()?;

        Ok(Self {
            device: Arc::new(device),
        })
    }
}

impl Stream for TunStream {
    fn read(&self, buffer: &mut [u8]) -> impl Future<Output = StreamResult<usize>> {
        async { self.device.recv(buffer).await }
    }

    fn write(&self, bytes: &[u8]) -> impl Future<Output = StreamResult<()>> {
        async {
            match self.device.send(bytes).await {
                Ok(size) => {
                    if size != bytes.len() {
                        let error_message = "Failed to write all bytes.".to_string();
                        crate::logging::debug(&error_message);
                        return Err(std::io::Error::other(error_message));
                    }

                    return Ok(());
                }

                Err(error) => return Err(error),
            };
        }
    }
}
