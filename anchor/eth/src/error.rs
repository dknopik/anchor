use alloy::transports::{RpcError, TransportErrorKind};
use thiserror::Error;

// Custom execution integration layer errors
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Sync Error: {0}")]
    SyncError(String),
    #[error("Invalid Event: {0}")]
    InvalidEvent(String),
    #[error("RPC Error: {0}")]
    RpcError(#[from] RpcError<TransportErrorKind>),
    #[error("WS Error: {0}")]
    WsError(String),
    #[error("Decode Error: {0}")]
    DecodeError(String),
    #[error("{0}")]
    Misc(String),
    #[error("Duplicate Error: {0}")]
    Duplicate(String),
    #[error("Database Error: {0}")]
    Database(String),
}
