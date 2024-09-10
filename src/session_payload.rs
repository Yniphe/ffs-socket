use ring::aead::LessSafeKey;
use crate::user::User;

pub struct SessionPayload {
    #[allow(dead_code)]
    payload: User,
    less_safe_key: Option<LessSafeKey>,
}

impl SessionPayload {
    pub fn new(payload: User, less_safe_key: Option<LessSafeKey>) -> Self {
        Self {
            payload,
            less_safe_key,
        }
    }

    pub fn less_safe_key(&self) -> Option<LessSafeKey> {
        self.less_safe_key.clone()
    }
}