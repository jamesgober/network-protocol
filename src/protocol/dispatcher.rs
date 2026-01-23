use crate::error::{ProtocolError, Result};
use crate::protocol::message::Message;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type HandlerFn = dyn Fn(&Message) -> Result<Message> + Send + Sync + 'static;

pub struct Dispatcher {
    handlers: Arc<RwLock<HashMap<String, Box<HandlerFn>>>>,
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
        match self.handlers.write() {
            Ok(mut handlers) => {
                handlers.insert(opcode.to_string(), Box::new(handler));
                Ok(())
            }
            Err(_) => Err(ProtocolError::Custom(
                "Failed to acquire write lock on dispatcher handlers".to_string(),
            )),
        }
    }

    pub fn dispatch(&self, msg: &Message) -> Result<Message> {
        let opcode = get_opcode(msg);

        let handlers = match self.handlers.read() {
            Ok(handlers) => handlers,
            Err(_) => {
                return Err(ProtocolError::Custom(
                    "Failed to acquire read lock on dispatcher handlers".to_string(),
                ))
            }
        };

        match handlers.get(&opcode) {
            Some(handler) => handler(msg),
            None => Err(ProtocolError::UnexpectedMessage),
        }
    }
}

/// Determine message type name for routing
fn get_opcode(msg: &Message) -> String {
    match msg {
        Message::Ping => "PING",
        Message::Pong => "PONG",
        Message::Echo(_) => "ECHO",
        // Secure handshake messages
        Message::SecureHandshakeInit { .. } => "SEC_HS_INIT",
        Message::SecureHandshakeResponse { .. } => "SEC_HS_RESP",
        Message::SecureHandshakeConfirm { .. } => "SEC_HS_CONFIRM",
        Message::Custom { command, .. } => command,
        Message::Disconnect => "DISCONNECT",
        Message::Unknown => "UNKNOWN",
    }
    .to_string()
}
