
use derive_new::new;
use super::error::Result;

use super::channel::Channel;


#[derive(new)]
pub struct Sender {
    channel: Channel,
}

impl Sender {
    pub async fn send(&mut self, data: impl Into<Vec<u8>>) -> Result<usize> {
        self.channel.write(data).await
    }

    pub async fn finish(self) -> Result<()> {
        self.channel.close().await
    }
}