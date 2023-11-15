use thiserror::Error;

use std::io;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to send whole packet (expected {0}, got {1})")]
    PartialSend(usize, usize),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("dns_message_parser decode error: {0}")]
    DnsDecode(#[from] dns_message_parser::DecodeError),
    #[error("dns_message_parser encode error: {0}")]
    DnsEncode(#[from] dns_message_parser::EncodeError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("hickory_proto error: {0}")]
    HickoryProto(#[from] hickory_proto::error::ProtoError),
}

pub type Result<T> = std::result::Result<T, Error>;
