/// Embedded (compiled-in) model assets.
///
/// This is only populated when the `embed-models` feature is enabled and
/// `AIEGIS_EMBED_PACKAGES` points to model files present at build time.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedModel {
    pub package: &'static str,
    pub model: &'static [u8],
    pub tokenizer: &'static [u8],
}

mod data {
    include!(concat!(env!("OUT_DIR"), "/aiegis_embedded_models.rs"));
}

pub fn get(package: &str) -> Option<&'static EmbeddedModel> {
    data::EMBEDDED_MODELS.iter().find(|entry| entry.package == package)
}
