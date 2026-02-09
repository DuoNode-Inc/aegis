//! Detection pipeline — orchestrates injection, PII, and entropy scanners.

pub mod classifier;
#[cfg(feature = "embed-models")]
pub mod embedded;
pub mod entropy;
pub mod injection;
pub mod model_package;
pub mod pii;
pub mod pipeline;
pub mod tokenizer;
