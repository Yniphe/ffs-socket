use ring::aead::LessSafeKey;
use crate::session_saturate::SessionSaturate;

pub struct SessionContext {
    pub less_safe_key: Option<LessSafeKey>,
    pub saturate: SessionSaturate,
}

impl SessionContext {
    pub fn new() -> Self {

        Self {
            less_safe_key: None,
            saturate: SessionSaturate::Init,
        }
    }

    pub fn set_pk(&mut self, pk: LessSafeKey) {
        self.less_safe_key = Option::from(pk)
    }

    pub fn pk(&self) -> Option<LessSafeKey> {
        self.less_safe_key.clone()
    }

    pub fn saturate(&mut self, saturate: SessionSaturate) {
        self.saturate = saturate;
    }
}