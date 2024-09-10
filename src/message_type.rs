#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Sign = 0x22,
    SignWaitApprove = 0x23,
    SignApprove = 0x24,
    Trace = 0x25,
    Undefined = 0x99,
}

impl From<MessageType> for u8 {
    fn from(v: MessageType) -> Self {
        v as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == MessageType::Sign as u8 => Ok(MessageType::Sign),
            x if x == MessageType::SignWaitApprove as u8 => Ok(MessageType::SignWaitApprove),
            x if x == MessageType::SignApprove as u8 => Ok(MessageType::SignApprove),
            x if x == MessageType::Trace as u8 => Ok(MessageType::Trace),
            _ => Err(()),
        }
    }
}