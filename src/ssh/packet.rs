use super::buffer::Buffer;

#[derive(Debug)]
pub struct Packet {
    pub len: u32,
    pub padding_len: u8,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl Packet {
    pub fn parse(data: &[u8], mac: Option<Vec<u8>>) -> Option<Self> {
        // let size = size.get_u32();

        let len = data.len() as u32;
        let data = Buffer::from_slice(data);

        // let mut data: &[u8] = &data;

        let padding_len = data.take_u8()?;

        let payload_len = data.len() - padding_len as usize;
        let payload = data.take_bytes(payload_len)?.to_vec();

        // println!("payload: {}, {}", payload_len, payload.len());
        // println!("payload: {}", String::from_utf8_lossy(payload.as_ref()));
        // println!("payload: {:?}", payload);

        let padding = data.take_bytes(padding_len as usize)?.to_vec();
        // let mut padding = vec![0; padding_len as usize];

        // Read::read_exact(&mut data, &mut padding)?;

        Some(Packet {
            len,
            padding_len,
            payload,
            padding,
            mac,
        })
    }
}
