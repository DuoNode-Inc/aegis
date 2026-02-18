//! Detection pipeline — orchestrates injection, PII, and entropy scanners.

pub mod classifier;
#[cfg(feature = "embed-models")]
pub mod embedded;
#[cfg(feature = "embed-llm-weights")]
pub mod embedded_llm;
pub mod entropy;
pub mod injection;
pub mod llm;
pub mod model_package;
pub mod pii;
pub mod pipeline;
pub mod supply_chain;
pub mod tokenizer;
pub mod web3;
