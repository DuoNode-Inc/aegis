//! Detection pipeline — orchestrates injection, PII, and entropy scanners.

pub mod entropy;
pub mod injection;
pub mod pii;
pub mod pipeline;
