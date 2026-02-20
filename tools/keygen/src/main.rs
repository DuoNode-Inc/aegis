//! aiegis-keygen — License key generation tool for Aiegis.
//!
//! **DuoNode Inc internal use only.** This binary holds the signing key and
//! should never be distributed to customers.
//!
//! ## Subcommands
//!
//! ```
//! # Generate a new Ed25519 keypair
//! aiegis-keygen keypair --output-dir ./keys
//!
//! # Sign a license key
//! aiegis-keygen generate \
//!     --user alice@example.com \
//!     --tier sentinel \
//!     --expiry 2027-01-01T00:00:00Z \
//!     --private-key-path ./keys/private.pem \
//!     --key-version 1
//! ```

mod claims;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use claims::LicenseClaims;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "aiegis-keygen",
    about = "Aiegis license key generation tool — DuoNode Inc internal use only",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair for license signing.
    ///
    /// Writes `private.pem` (PKCS8 PEM, keep secret!) and `public.b64`
    /// (base64 SPKI DER, embed in the aiegis binary) to --output-dir.
    Keypair {
        /// Directory to write key files into. Created if it doesn't exist.
        #[arg(long)]
        output_dir: PathBuf,
    },

    /// Sign and issue a new license key.
    ///
    /// Outputs the license key string to stdout. Pipe to a file or copy to
    /// the customer's `~/.aiegis/license.key`.
    Generate {
        /// Licensee email address.
        #[arg(long)]
        user: String,

        /// Licensed tier: "shield" or "sentinel".
        #[arg(long, value_parser = parse_tier)]
        tier: String,

        /// Expiry timestamp in ISO 8601 UTC format (e.g. "2027-01-01T00:00:00Z").
        #[arg(long)]
        expiry: String,

        /// Path to the PKCS8 PEM private key file.
        #[arg(long)]
        private_key_path: PathBuf,

        /// Key version (selects which compiled-in public key verifies this license).
        #[arg(long, default_value = "1")]
        key_version: u8,
    },
}

fn parse_tier(s: &str) -> Result<String, String> {
    match s.to_ascii_lowercase().as_str() {
        "shield" | "sentinel" | "developer" => Ok(s.to_ascii_lowercase()),
        _ => Err(format!(
            "Invalid tier '{s}'. Expected one of: shield, sentinel"
        )),
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keypair { output_dir } => cmd_keypair(&output_dir),
        Commands::Generate {
            user,
            tier,
            expiry,
            private_key_path,
            key_version,
        } => cmd_generate(&user, &tier, &expiry, &private_key_path, key_version),
    }
}

// ─── keypair ─────────────────────────────────────────────────────────────────

fn cmd_keypair(output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create directory: {}", output_dir.display()))?;

    // Generate a fresh Ed25519 keypair using OS entropy
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Write private key as PKCS8 PEM
    let private_pem_path = output_dir.join("private.pem");
    signing_key
        .write_pkcs8_pem_file(&private_pem_path, LineEnding::LF)
        .with_context(|| {
            format!(
                "Failed to write private key to {}",
                private_pem_path.display()
            )
        })?;

    // chmod 600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&private_pem_path, perms)?;
    }

    // Write public key as base64 SPKI DER (format expected by license.rs)
    let spki_der = verifying_key
        .to_public_key_der()
        .context("Failed to encode public key as SPKI DER")?;
    let public_b64 = BASE64.encode(spki_der.as_bytes());
    let public_b64_path = output_dir.join("public.b64");
    std::fs::write(&public_b64_path, &public_b64)
        .with_context(|| format!("Failed to write public key to {}", public_b64_path.display()))?;

    eprintln!("✓ Keypair generated:");
    eprintln!("  Private key: {} (keep secret!)", private_pem_path.display());
    eprintln!("  Public key:  {} (embed in binary)", public_b64_path.display());
    eprintln!();
    eprintln!("Update AIEGIS_PUBLIC_KEY_V1_B64 in src/license.rs with:");
    eprintln!("{public_b64}");

    Ok(())
}

// ─── generate ────────────────────────────────────────────────────────────────

fn cmd_generate(
    user: &str,
    tier: &str,
    expiry: &str,
    private_key_path: &Path,
    key_version: u8,
) -> Result<()> {
    // Validate expiry is parseable
    expiry
        .parse::<chrono::DateTime<chrono::Utc>>()
        .with_context(|| {
            format!(
                "Invalid expiry timestamp '{expiry}'. Use ISO 8601 UTC, e.g. 2027-01-01T00:00:00Z"
            )
        })?;

    if key_version == 0 {
        return Err(anyhow!("key_version must be >= 1"));
    }

    // Load private key from PKCS8 PEM
    let signing_key = SigningKey::read_pkcs8_pem_file(private_key_path).with_context(|| {
        format!(
            "Failed to load private key from {}",
            private_key_path.display()
        )
    })?;

    // Build claims
    let claims = LicenseClaims {
        user: user.to_string(),
        tier: tier.to_string(),
        expiry: expiry.to_string(),
        features: vec![],
        key_version,
    };

    // Serialize claims to JSON bytes — this is the payload
    let payload = serde_json::to_vec(&claims).context("Failed to serialize claims to JSON")?;

    // Sign the payload
    let signature = signing_key.sign(&payload);

    // Format: {base64_signature}.{base64_payload}
    let license_key = format!(
        "{}.{}",
        BASE64.encode(signature.to_bytes()),
        BASE64.encode(&payload),
    );

    // Print the license key to stdout (ready to save or pipe)
    println!("{license_key}");

    eprintln!();
    eprintln!("✓ License issued:");
    eprintln!("  User:        {user}");
    eprintln!("  Tier:        {tier}");
    eprintln!("  Expiry:      {expiry}");
    eprintln!("  Key version: {key_version}");
    eprintln!();
    eprintln!("Install on the customer's machine:");
    eprintln!("  aiegis license activate <key>");
    eprintln!("or:");
    eprintln!("  mkdir -p ~/.aiegis && echo '<key>' > ~/.aiegis/license.key");

    Ok(())
}
