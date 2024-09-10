use std::io::{Cursor, Read};
use ring::aead::{Aad, Nonce, LessSafeKey};
use crate::message_type::MessageType;

pub struct PacketDecoder {
    cursor: Cursor<Vec<u8>>,
}

impl PacketDecoder {
    pub fn new_xor(buf: &[u8], shared: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(buf.iter()
                .enumerate()
                .map(|(i, &byte)| byte ^ shared[i % shared.len()])
                .collect())
        }
    }

    pub fn new(buf: &[u8], shared: Option<LessSafeKey>) -> Self {
        if let Some(shared) = shared {
            let packet_len = buf.len();
            let nonce = &buf[packet_len - 12..packet_len];
            let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();

            let mut data = buf[..packet_len - 12].to_vec();
            if shared.open_in_place(nonce, Aad::empty(), &mut data).is_ok() {
                return Self {
                    cursor: Cursor::new(data)
                };
            }
        }

        Self {
            cursor: Cursor::new(buf.to_vec())
        }
    }

    pub fn read_uint32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.cursor.read_exact(&mut buf).unwrap();
        u32::from_be_bytes(buf)
    }

    pub fn read_uint16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.cursor.read_exact(&mut buf).unwrap();
        u16::from_be_bytes(buf)
    }

    pub fn read_opcode(&mut self) -> MessageType {
        let opcode = self.read_uint8();
        MessageType::try_from(opcode).unwrap_or(MessageType::Undefined)
    }

    pub fn read_string(&mut self) -> Vec<u8> {
        let length = self.read_uint32();
        let mut buf = vec![0; length as usize];
        self.cursor.read_exact(&mut buf).unwrap();
        buf
    }

    pub fn read_uint8(&mut self) -> u8 {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf).unwrap();
        buf[0]
    }
}
