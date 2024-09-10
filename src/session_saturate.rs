#[derive(Eq, PartialEq, Clone, Copy)]
pub enum SessionSaturate {
    Init,
    WaitApprove,
    Success,
}