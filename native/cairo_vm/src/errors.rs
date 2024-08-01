use rustler::{Encoder, Env, Term};

#[derive(Debug)]
pub(crate) enum CairoVMError {
    InvalidProgramContent,
    InvalidInputJSON,
    RuntimeError(String),
}

impl std::fmt::Display for CairoVMError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoVMError::InvalidProgramContent => write!(f, "Invalid program content"),
            CairoVMError::InvalidInputJSON => write!(f, "Invalid input JSON"),
            CairoVMError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
        }
    }
}

impl Encoder for CairoVMError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}
