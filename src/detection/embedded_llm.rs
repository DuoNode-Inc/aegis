/// Embedded (compiled-in) GGUF LLM weights.
///
/// This is only populated when the `embed-llm-weights` feature is enabled and
/// `AIEGIS_EMBED_LLM_GGUF_PATH` points to a GGUF file present at build time.
///
/// Note: the model bytes are large; this feature is intended for single-file
/// distributions (air-gapped installs, appliance builds).

mod data {
    include!(concat!(env!("OUT_DIR"), "/aiegis_embedded_llm.rs"));
}

pub fn name() -> &'static str {
    data::EMBEDDED_LLM_GGUF_NAME
}

pub fn len() -> usize {
    data::EMBEDDED_LLM_GGUF_LEN
}

pub fn bytes() -> &'static [u8] {
    data::EMBEDDED_LLM_GGUF_BYTES
}

