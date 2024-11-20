use rustler::{Encoder, Env, Term};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CairoVMError {
    #[error("Invalid program content")]
    InvalidProgramContent,
    #[error("Invalid input JSON")]
    InvalidInputJSON,
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

impl Encoder for CairoVMError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

impl From<CairoVMError> for rustler::Error {
    fn from(e: CairoVMError) -> Self {
        rustler::Error::Term(Box::new(e))
    }
}
