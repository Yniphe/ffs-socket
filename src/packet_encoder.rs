use ring::aead::{Aad, LessSafeKey, Nonce};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Write;
use crate::message_type::MessageType;

pub struct PacketEncoder {
    buf: Vec<u8>,
}

impl PacketEncoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn write_u8(&mut self, value: u8) {
        self.buf.write_all(&[value]).unwrap();
    }

    #[allow(dead_code)]
    pub fn write_u16(&mut self, value: u16) {
        self.buf.write_all(&value.to_be_bytes()).unwrap();
    }

    #[allow(dead_code)]
    pub fn write_u32(&mut self, value: u32) {
        self.buf.write_all(&value.to_be_bytes()).unwrap();
    }

    #[allow(dead_code)]
    pub fn write_opcode(&mut self, value: MessageType) {
        self.buf.write_all(&[value.into()]).unwrap();
    }

    #[allow(dead_code)]
    pub fn write_string(&mut self, value: &[u8]) {
        self.write_u32(value.len() as u32);
        self.buf.write_all(value).unwrap();
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self, shared: Option<LessSafeKey>) -> Vec<u8> {
        if let Some(shared) = shared {
            let rng = SystemRandom::new();
            let mut nonce_bytes = [0u8; 12];

            rng.fill(&mut nonce_bytes).unwrap();

            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut buf = self.buf.clone();

            shared.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).unwrap();
            buf.extend_from_slice(&nonce_bytes);

            return buf;
        }

        self.buf.clone()
    }

    pub fn to_bytes_with_xor(&self, shared: Vec<u8>) -> Vec<u8> {
        self.buf.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ shared[i % shared.len()])
            .collect()
    }
}