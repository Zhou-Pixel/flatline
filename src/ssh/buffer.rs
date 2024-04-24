use std::{
    cell::Cell, mem::size_of, ops::{Index, IndexMut}
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt, BE};

// todo: Improve performance
#[derive(Default, Clone, Debug)]
#[repr(transparent)]
pub struct Buffer<T>(T);

// impl From<Buffer> for Vec<u8> {
//     fn from(value: Buffer) -> Self {
//         value.into_vec()
//     }
// }

// impl From<Vec<u8>> for Buffer {
//     fn from(value: Vec<u8>) -> Self {
//         Self(value)
//     }
// }

impl<T: AsRef<[u8]>> AsRef<[u8]> for Buffer<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<I, T: Index<I>> Index<I> for Buffer<T> {
    type Output = T::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.0.index(index)
    }
}

impl<I, T: IndexMut<I>> IndexMut<I> for Buffer<T> {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}

// impl IntoIterator for Buffer {
//     type Item = u8;

//     type IntoIter = IntoIter<u8>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.0.into_iter()
//     }
// }

// impl<T> Extend<T> for Buffer {

//     fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
//             self.0.extend(iter)
//     }

//     #[inline]
//     fn extend_one(&mut self, item: T) {
//         self.0.extend_one(item)
//     }

//     #[inline]
//     fn extend_reserve(&mut self, additional: usize) {
//         todo!()
//     }
// }

impl Buffer<Cell<&[u8]>> {
    pub fn from_slice(slice: &[u8]) -> Buffer<Cell<&[u8]>> {
        Buffer(Cell::new(slice))
    }

    pub fn take_u8(&self) -> Option<u8> {
        if self.0.get().is_empty() {
            None
        } else {
            let ret = self.0.get()[0];
            self.0.set(&self.0.get()[1..]);
            Some(ret)
        }
    }

    pub fn take_u32(&self) -> Option<u32> {
        if self.len() < size_of::<u32>() {
            None
        } else {
            let mut tmp = self.0.get();
            let ret = ReadBytesExt::read_u32::<BigEndian>(&mut tmp).unwrap();
            self.0.set(tmp);
            Some(ret)
        }
    }

    // pub fn take_u64(&self) -> Option<u64> {
    //     if self.len() < size_of::<u64>() {
    //         None
    //     } else {
    //         let mut tmp = self.0.get();
    //         let ret = ReadBytesExt::read_u64::<BigEndian>(&mut tmp).unwrap();
    //         self.0.set(tmp);
    //         Some(ret)
    //     }
    // }

    pub fn take_bytes(&self, len: usize) -> Option<&[u8]> {
        if self.0.get().len() < len {
            None
        } else {
            let ret = &self.0.get()[..len];
            self.0.set(&self.0.get()[len..]);
            Some(ret)
        }
    }

    pub fn take_one(&self) -> Option<(u32, &[u8])> {
        let tmp = self.0.get();

        let len = match self.take_u32() {
            Some(len) => len,
            None => {
                self.0.set(tmp);
                return None;
            },
        } as usize;

        if self.len() < len {
            return None;
        }


        let ret = &self.0.get()[..len];

        self.0.set(&self.0.get()[len..]);

        Some((len as u32, ret))

    }

   
    pub fn len(&self) -> usize {
        self.0.get().len()
    }
}

impl Buffer<Vec<u8>> {
    pub fn from_one(content: impl AsRef<[u8]>) -> Self {
        let content = content.as_ref();
        let mut vec = Vec::with_capacity(content.len() + size_of::<u32>());
        let mut size = [0u8; size_of::<u32>()];
        size.as_mut().write_u32::<BE>(content.len() as u32).unwrap();

        vec.extend(size);
        vec.extend(content);
        Self(vec)
    }

    pub fn new() -> Self {
        Default::default()
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        Buffer(vec)
    }

    pub fn put_u64(&mut self, num: u64) {
        let mut buf = [0; size_of::<u64>()];

        buf.as_mut().write_u64::<BE>(num).unwrap();

        self.0.extend(buf);
    }

    pub fn put_u32(&mut self, num: u32) {
        let mut buf = [0; size_of::<u32>()];
        buf.as_mut().write_u32::<BE>(num).unwrap();
        // WriteBytesExt::write_u32::<BE>(&mut buf.as_mut_slice(), num).unwrap();
        self.0.extend(buf);
    }

    pub fn put_u8(&mut self, num: u8) {
        self.0.push(num);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn take_u64(&mut self) -> Option<u64> {
        let mut buf: &[u8] = &self.0;
        let Ok(num) = ReadBytesExt::read_u64::<BE>(&mut buf) else {
            return None;
        };

        self.0.drain(..size_of::<u64>());

        Some(num)
    }

    pub fn take_u32(&mut self) -> Option<u32> {
        let mut buf: &[u8] = &self.0;

        let Ok(num) = ReadBytesExt::read_u32::<BE>(&mut buf) else {
            return None;
        };

        self.0.drain(..size_of::<u32>());

        Some(num)
    }

    pub fn take_u8(&mut self) -> Option<u8> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        }
        // self.take_bytes(1).map(|v| v[0])
    }

    pub fn take_bytes(&mut self, size: usize) -> Option<Vec<u8>> {
        if self.0.len() < size {
            None
        } else {
            Some(self.0.drain(..size).collect())
        }
    }

    pub fn take_one(&mut self) -> Option<(u32, Vec<u8>)> {
        if self.0.len() < size_of::<u32>() {
            return None;
        }

        let mut buf: &[u8] = &self.0;

        let Ok(size) = ReadBytesExt::read_u32::<BE>(&mut buf) else {
            return None;
        };

        if buf.len() < size as usize {
            return None;
        }

        self.0.drain(0..4); // remove size 4 bytes

        Some((size, self.0.drain(0..size as usize).collect()))
    }

    pub fn put_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.extend(bytes.as_ref());
    }

    pub fn put_one(&mut self, content: impl AsRef<[u8]>) {
        self.put_u32(content.as_ref().len() as u32);

        self.put_bytes(content);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn extend<T: IntoIterator<Item = u8>>(&mut self, other: T) {
        self.0.extend(other);
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}
