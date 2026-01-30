use crate::error::{ProtocolError, Result};
use crate::protocol::message::Message;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type HandlerFn = dyn Fn(&Message) -> Result<Message> + Send + Sync + 'static;

/// Message dispatcher with zero-copy opcode routing for statics.
/// Uses Cow<'static, str> to avoid heap allocations for known message types.
pub struct Dispatcher {
    handlers: Arc<RwLock<HashMap<Cow<'static, str>, Box<HandlerFn>>>>,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register<F>(&self, opcode: &str, handler: F) -> Result<()>
    where
        F: Fn(&Message) -> Result<Message> + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().map_err(|_| {
            ProtocolError::Custom("Failed to acquire write lock on dispatcher".to_string())
        })?;

        handlers.insert(Cow::Owned(opcode.to_string()), Box::new(handler));
        Ok(())
    }

    pub fn dispatch(&self, msg: &Message) -> Result<Message> {
        let opcode = get_opcode(msg);

        let handlers = self.handlers.read().map_err(|_| {
            ProtocolError::Custom("Failed to acquire read lock on dispatcher".to_string())
        })?;

        handlers
            .get(opcode.as_ref())
            .ok_or(ProtocolError::UnexpectedMessage)
            .and_then(|handler| handler(msg))
    }
}

/// Determine message type name for routing (zero-copy for known message types).
/// Returns Cow::Borrowed for static message type opcodes, avoiding allocations in hot path.
/// For custom commands, returns Cow::Owned since the string comes from the message.
#[inline]
fn get_opcode(msg: &Message) -> Cow<'static, str> {
    match msg {
        Message::Ping => Cow::Borrowed("PING"),
        Message::Pong => Cow::Borrowed("PONG"),
        Message::Echo(_) => Cow::Borrowed("ECHO"),
        Message::SecureHandshakeInit { .. } => Cow::Borrowed("SEC_HS_INIT"),
        Message::SecureHandshakeResponse { .. } => Cow::Borrowed("SEC_HS_RESP"),
        Message::SecureHandshakeConfirm { .. } => Cow::Borrowed("SEC_HS_CONFIRM"),
        Message::Custom { command, .. } => Cow::Owned(command.clone()),
        Message::Disconnect => Cow::Borrowed("DISCONNECT"),
        Message::Unknown => Cow::Borrowed("UNKNOWN"),
    }
}
