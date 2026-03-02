//! Bitwarden PM WASM guest plugin for rosec.
//!
//! This is the Extism guest that implements the Bitwarden Password Manager
//! provider.  It exports plugin functions that the `rosec-wasm` host crate
//! calls via `Plugin::call()`.
//!
//! # Architecture
//!
//! - **Global state**: A `Mutex<Option<GuestState>>` holds the plugin's
//!   mutable state.  `init` populates `GuestConfig`; `unlock` populates
//!   `AuthState` (access token, refresh token, `VaultState`).
//! - **No async**: All functions are synchronous — HTTP goes through
//!   `extism_pdk::http::request`, not `reqwest`.
//! - **No notifications**: The host handles real-time sync nudges; the
//!   guest only does poll-based sync.
//! - **No OAuth credential storage**: Device registration credentials
//!   are passed from the host via `UnlockRequest.registration_fields`.

mod api;
mod cipher;
mod crypto;
mod error;
mod protocol;
mod vault;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use extism_pdk::*;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ServerUrls, TwoFactorSubmission};
use crate::error::BitwardenError;
use crate::protocol::*;
use crate::vault::{CipherType, DecryptedCipher, DecryptedField, VaultState};

// ═══════════════════════════════════════════════════════════════════
// Global state
// ═══════════════════════════════════════════════════════════════════

/// Global guest state behind a mutex.
///
/// `None` before `init` is called; `Some(GuestState)` after.
static STATE: Mutex<Option<GuestState>> = Mutex::new(None);

/// Top-level guest state.
struct GuestState {
    config: GuestConfig,
    auth: Option<AuthState>,
}

/// One-time configuration injected by `init`.
struct GuestConfig {
    provider_id: String,
    email: String,
    urls: ServerUrls,
    device_id: String,
}

/// Authenticated state — populated by `unlock`, cleared by `lock`.
struct AuthState {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    vault: VaultState,
}

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Attribute key for item type — mirrors `rosec_core::ATTR_TYPE`.
const ATTR_TYPE: &str = "rosec:type";

/// PEM headers that indicate an SSH private key in a text field.
const PEM_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

// ═══════════════════════════════════════════════════════════════════
// Attribute catalogue (35 descriptors)
// ═══════════════════════════════════════════════════════════════════

/// Build the full attribute descriptor catalogue.
///
/// Returns the same 35 descriptors as native `BITWARDEN_ATTRIBUTES` but
/// serialised as `WasmAttributeDescriptor` for JSON transport.
fn bitwarden_attribute_descriptors() -> Vec<WasmAttributeDescriptor> {
    vec![
        // -- Common (all item types) --
        desc("name", false, &[], "Item display name"),
        desc(ATTR_TYPE, false, &[], "Item type (login, note, card, identity, sshkey)"),
        desc("folder", false, &[], "Folder name (if assigned)"),
        desc("notes", true, &[], "Free-form notes (always sensitive)"),
        // -- Login --
        desc("username", false, &["login"], "Login username (public per attribute-model decision)"),
        desc("password", true, &["login"], "Login password"),
        desc("totp", true, &["login"], "TOTP seed / otpauth URI"),
        desc("uri", false, &["login"], "Primary login URI"),
        // -- Card --
        desc("cardholder", true, &["card"], "Cardholder name (PII)"),
        desc("number", true, &["card"], "Card number"),
        desc("brand", false, &["card"], "Card brand (Visa, Mastercard, etc.)"),
        desc("exp_month", true, &["card"], "Card expiration month"),
        desc("exp_year", true, &["card"], "Card expiration year"),
        desc("code", true, &["card"], "Card security code (CVV)"),
        // -- SSH Key --
        desc("private_key", true, &["sshkey"], "SSH private key"),
        desc("public_key", false, &["sshkey"], "SSH public key"),
        desc("fingerprint", false, &["sshkey"], "SSH key fingerprint"),
        // -- Identity (all PII → sensitive) --
        desc("title", true, &["identity"], "Identity title (Mr, Ms, etc.)"),
        desc("first_name", true, &["identity"], "First name"),
        desc("middle_name", true, &["identity"], "Middle name"),
        desc("last_name", true, &["identity"], "Last name"),
        desc("username", true, &["identity"], "Identity username (PII)"),
        desc("company", true, &["identity"], "Company name"),
        desc("ssn", true, &["identity"], "Social Security Number"),
        desc("passport_number", true, &["identity"], "Passport number"),
        desc("license_number", true, &["identity"], "Driver's license number"),
        desc("email", true, &["identity"], "Identity email address (PII)"),
        desc("phone", true, &["identity"], "Identity phone number (PII)"),
        desc("address1", true, &["identity"], "Address line 1"),
        desc("address2", true, &["identity"], "Address line 2"),
        desc("address3", true, &["identity"], "Address line 3"),
        desc("city", true, &["identity"], "City"),
        desc("state", true, &["identity"], "State / province"),
        desc("postal_code", true, &["identity"], "Postal / ZIP code"),
        desc("country", true, &["identity"], "Country"),
    ]
}

/// Helper: build a `WasmAttributeDescriptor`.
fn desc(name: &str, sensitive: bool, item_types: &[&str], description: &str) -> WasmAttributeDescriptor {
    WasmAttributeDescriptor {
        name: name.to_string(),
        sensitive,
        item_types: item_types.iter().map(|s| (*s).to_string()).collect(),
        description: description.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helper functions (ported from native provider.rs)
// ═══════════════════════════════════════════════════════════════════

/// Populate public (non-sensitive) attributes for a decrypted cipher.
///
/// Port of `BitwardenProvider::populate_public_attrs`.
fn populate_public_attrs(attrs: &mut HashMap<String, String>, dc: &DecryptedCipher) {
    // xdg:schema — required for Secret Service compatibility
    let schema = match dc.cipher_type {
        CipherType::Login => "org.freedesktop.Secret.Generic",
        CipherType::SecureNote => "org.freedesktop.Secret.Note",
        _ => "org.freedesktop.Secret.Generic",
    };
    attrs.insert("xdg:schema".to_string(), schema.to_string());
    attrs.insert(ATTR_TYPE.to_string(), dc.cipher_type.as_str().to_string());

    if let Some(folder) = &dc.folder_name {
        attrs.insert("folder".to_string(), folder.clone());
    }
    if let Some(org_id) = &dc.organization_id {
        attrs.insert("org_id".to_string(), org_id.clone());
    }
    if let Some(org_name) = &dc.organization_name {
        attrs.insert("org".to_string(), org_name.clone());
    }

    // Login-specific public attributes
    if let Some(login) = &dc.login {
        // username is public per attribute-model decision
        if let Some(username) = &login.username {
            attrs.insert("username".to_string(), username.as_str().to_string());
        }
        // All URIs are public. First is "uri" (index 0); subsequent are "uri.1", "uri.2", etc.
        for (i, uri) in login.uris.iter().enumerate() {
            let key = if i == 0 {
                "uri".to_string()
            } else {
                format!("uri.{i}")
            };
            attrs.insert(key, uri.clone());
        }
    }

    // Card-specific public attributes (brand only — cardholder is PII/sensitive)
    if let Some(card) = &dc.card
        && let Some(brand) = &card.brand
    {
        attrs.insert("brand".to_string(), brand.clone());
    }

    // SSH key public attributes
    if let Some(ssh_key) = &dc.ssh_key {
        if let Some(pub_key) = &ssh_key.public_key {
            attrs.insert("public_key".to_string(), pub_key.clone());
        }
        if let Some(fp) = &ssh_key.fingerprint {
            attrs.insert("fingerprint".to_string(), fp.clone());
        }
    }

    // Custom fields as attributes — only text (type 0), boolean (type 2),
    // and linked (type 3). Hidden fields (type 1) are sensitive and excluded.
    for (key, value) in index_custom_fields(&dc.fields, &[0, 2, 3]) {
        attrs.insert(key, value);
    }
}

/// Convert a `SystemTime` to seconds since the Unix epoch.
fn to_epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a `WasmItemMeta` from a decrypted cipher.
///
/// Port of `BitwardenProvider::cipher_to_meta`.
fn cipher_to_wasm_meta(provider_id: &str, dc: &DecryptedCipher) -> WasmItemMeta {
    let mut attributes = HashMap::new();
    populate_public_attrs(&mut attributes, dc);

    let created = dc.creation_date.as_ref().and_then(|s| parse_iso8601(s));
    let modified = dc.revision_date.as_ref().and_then(|s| parse_iso8601(s));

    // Inject provider_id attribute for the host (mirrors rosec:provider)
    attributes.insert("rosec:provider".to_string(), provider_id.to_string());

    WasmItemMeta {
        id: dc.id.clone(),
        label: dc.name.clone(),
        attributes,
        created_epoch_secs: created.map(to_epoch_secs),
        modified_epoch_secs: modified.map(to_epoch_secs),
    }
}

/// Build item attributes (public + secret names) for a decrypted cipher.
///
/// Port of `BitwardenProvider::build_item_attributes`.
fn build_item_attributes(provider_id: &str, dc: &DecryptedCipher) -> (HashMap<String, String>, Vec<String>) {
    let mut public = HashMap::new();
    let mut secret_names = Vec::new();

    // Shared public attributes (schema, type, folder, org, login, card, ssh, custom fields)
    populate_public_attrs(&mut public, dc);

    // provider_id is only in ItemAttributes, not ItemMeta
    public.insert("provider_id".to_string(), provider_id.to_string());

    // notes — always sensitive
    if dc.notes.is_some() {
        secret_names.push("notes".to_string());
    }

    // -- Login sensitive --
    if let Some(login) = &dc.login {
        if login.password.is_some() {
            secret_names.push("password".to_string());
        }
        if login.totp.is_some() {
            secret_names.push("totp".to_string());
        }
    }

    // -- Card sensitive --
    if let Some(card) = &dc.card {
        if card.cardholder_name.is_some() {
            secret_names.push("cardholder".to_string());
        }
        if card.number.is_some() {
            secret_names.push("number".to_string());
        }
        if card.exp_month.is_some() {
            secret_names.push("exp_month".to_string());
        }
        if card.exp_year.is_some() {
            secret_names.push("exp_year".to_string());
        }
        if card.code.is_some() {
            secret_names.push("code".to_string());
        }
    }

    // -- SSH Key sensitive --
    if let Some(ssh_key) = &dc.ssh_key
        && ssh_key.private_key.is_some()
    {
        secret_names.push("private_key".to_string());
    }

    // -- Identity (all fields are sensitive PII) --
    if let Some(ident) = &dc.identity {
        let ident_fields: &[(&str, &Option<Zeroizing<String>>)] = &[
            ("title", &ident.title),
            ("first_name", &ident.first_name),
            ("middle_name", &ident.middle_name),
            ("last_name", &ident.last_name),
            ("username", &ident.username),
            ("company", &ident.company),
            ("ssn", &ident.ssn),
            ("passport_number", &ident.passport_number),
            ("license_number", &ident.license_number),
            ("email", &ident.email),
            ("phone", &ident.phone),
            ("address1", &ident.address1),
            ("address2", &ident.address2),
            ("address3", &ident.address3),
            ("city", &ident.city),
            ("state", &ident.state),
            ("postal_code", &ident.postal_code),
            ("country", &ident.country),
        ];
        for (name, value) in ident_fields {
            if value.is_some() {
                secret_names.push((*name).to_string());
            }
        }
    }

    // -- Hidden custom fields are sensitive --
    for (key, _) in index_custom_fields(&dc.fields, &[1]) {
        secret_names.push(key);
    }

    (public, secret_names)
}

/// Resolve a named secret attribute from a decrypted cipher.
///
/// Returns base64-encoded secret bytes, or `None` if the attribute
/// doesn't exist or has no value.
///
/// Port of `BitwardenProvider::resolve_secret_attr`.
fn resolve_secret_attr(dc: &DecryptedCipher, attr: &str) -> Option<Vec<u8>> {
    /// Helper: convert a `Zeroizing<String>` to bytes.
    fn to_bytes(s: &Zeroizing<String>) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    // notes — common to all types
    if attr == "notes" {
        return dc.notes.as_ref().map(to_bytes);
    }

    // Custom fields (prefixed with "custom.")
    if let Some(custom_name) = attr.strip_prefix("custom.") {
        let (base_name, occurrence) = match custom_name.rsplit_once('.') {
            Some((base, suffix)) => match suffix.parse::<usize>() {
                Ok(idx) => (base, idx),
                Err(_) => (custom_name, 0),
            },
            None => (custom_name, 0),
        };
        let mut count = 0usize;
        for field in &dc.fields {
            if field.name.as_deref() == Some(base_name) {
                if count == occurrence {
                    return field.value.as_ref().map(to_bytes);
                }
                count += 1;
            }
        }
        return None;
    }

    // Type-specific attributes
    match dc.cipher_type {
        CipherType::Login => {
            let login = dc.login.as_ref()?;
            match attr {
                "password" => login.password.as_ref().map(to_bytes),
                "totp" => login.totp.as_ref().map(to_bytes),
                "username" => login.username.as_ref().map(to_bytes),
                _ => None,
            }
        }
        CipherType::Card => {
            let card = dc.card.as_ref()?;
            match attr {
                "cardholder" => card.cardholder_name.as_ref().map(to_bytes),
                "number" => card.number.as_ref().map(to_bytes),
                "exp_month" => card.exp_month.as_ref().map(to_bytes),
                "exp_year" => card.exp_year.as_ref().map(to_bytes),
                "code" => card.code.as_ref().map(to_bytes),
                _ => None,
            }
        }
        CipherType::SshKey => {
            let ssh = dc.ssh_key.as_ref()?;
            match attr {
                "private_key" => ssh.private_key.as_ref().map(to_bytes),
                _ => None,
            }
        }
        CipherType::Identity => {
            let ident = dc.identity.as_ref()?;
            match attr {
                "title" => ident.title.as_ref().map(to_bytes),
                "first_name" => ident.first_name.as_ref().map(to_bytes),
                "middle_name" => ident.middle_name.as_ref().map(to_bytes),
                "last_name" => ident.last_name.as_ref().map(to_bytes),
                "username" => ident.username.as_ref().map(to_bytes),
                "company" => ident.company.as_ref().map(to_bytes),
                "ssn" => ident.ssn.as_ref().map(to_bytes),
                "passport_number" => ident.passport_number.as_ref().map(to_bytes),
                "license_number" => ident.license_number.as_ref().map(to_bytes),
                "email" => ident.email.as_ref().map(to_bytes),
                "phone" => ident.phone.as_ref().map(to_bytes),
                "address1" => ident.address1.as_ref().map(to_bytes),
                "address2" => ident.address2.as_ref().map(to_bytes),
                "address3" => ident.address3.as_ref().map(to_bytes),
                "city" => ident.city.as_ref().map(to_bytes),
                "state" => ident.state.as_ref().map(to_bytes),
                "postal_code" => ident.postal_code.as_ref().map(to_bytes),
                "country" => ident.country.as_ref().map(to_bytes),
                _ => None,
            }
        }
        CipherType::SecureNote | CipherType::Unknown(_) => None,
    }
}

// ── SSH key helpers ──────────────────────────────────────────────

/// Return `true` if `text` contains a recognised PEM private key header.
fn contains_pem(text: &str) -> bool {
    PEM_HEADERS.iter().any(|h| text.contains(h))
}

/// Extract the first PEM block from `text`, or `None`.
fn extract_pem_from_text(text: &str) -> Option<Zeroizing<String>> {
    for header in PEM_HEADERS {
        if let Some(start) = text.find(header) {
            let after = &text[start..];
            if let Some(end_marker) = after.find("-----END ") {
                let after_end = &after[end_marker..];
                let line_end = after_end.find('\n').unwrap_or(after_end.len());
                let pem = &after[..end_marker + line_end + 1];
                return Some(Zeroizing::new(pem.to_string()));
            }
        }
    }
    None
}

/// Extract the first recognisable PEM private key from any field of `dc`.
///
/// Search order: native `ssh_key.private_key` -> `notes` -> `login.password`
/// -> hidden custom fields (type 1).
fn extract_pem(dc: &DecryptedCipher) -> Option<Zeroizing<String>> {
    // 1. Native SSH key item
    if let Some(sk) = &dc.ssh_key
        && let Some(pk) = &sk.private_key
        && !pk.is_empty()
    {
        return Some(pk.clone());
    }

    // 2. Notes
    if let Some(notes) = &dc.notes
        && contains_pem(notes)
    {
        return extract_pem_from_text(notes);
    }

    // 3. Login password
    if let Some(login) = &dc.login
        && let Some(pw) = &login.password
        && contains_pem(pw)
    {
        return extract_pem_from_text(pw);
    }

    // 4. Hidden custom fields (field_type == 1)
    for field in &dc.fields {
        if field.field_type == 1
            && let Some(val) = &field.value
            && contains_pem(val)
        {
            return extract_pem_from_text(val);
        }
    }

    None
}

/// Build a `WasmSshKeyMeta` for a cipher that has discoverable SSH key
/// material, or `None` if the cipher has none.
///
/// Port of `BitwardenProvider::cipher_to_ssh_key_meta`.
fn cipher_to_ssh_key_meta(_provider_id: &str, dc: &DecryptedCipher) -> Option<WasmSshKeyMeta> {
    // Does this cipher have any SSH key material?
    let has_native_key = dc
        .ssh_key
        .as_ref()
        .is_some_and(|sk| sk.private_key.as_ref().is_some_and(|pk| !pk.is_empty()));

    let has_pem = !has_native_key && extract_pem(dc).is_some();

    if !has_native_key && !has_pem {
        return None;
    }

    let public_key_openssh = dc.ssh_key.as_ref().and_then(|sk| sk.public_key.clone());
    let fingerprint = dc.ssh_key.as_ref().and_then(|sk| sk.fingerprint.clone());

    // Extract custom.ssh_host / custom.ssh-host fields.
    let ssh_hosts: Vec<String> = dc
        .fields
        .iter()
        .filter(|f| matches!(f.name.as_deref(), Some("ssh_host" | "ssh-host")))
        .filter_map(|f| f.value.as_ref())
        .flat_map(|v| v.as_str().lines())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    // Extract custom.ssh_user / custom.ssh-user field (first wins).
    let ssh_user = dc
        .fields
        .iter()
        .filter(|f| matches!(f.name.as_deref(), Some("ssh_user" | "ssh-user")))
        .filter_map(|f| f.value.as_ref())
        .map(|v| v.as_str().trim().to_string())
        .find(|s| !s.is_empty());

    // Extract custom.ssh_confirm / custom.ssh-confirm flag.
    let require_confirm = dc.fields.iter().any(|f| {
        matches!(f.name.as_deref(), Some("ssh_confirm" | "ssh-confirm"))
            && f.value.as_ref().map(|v| v.as_str()) == Some("true")
    });

    let revision_date = dc.revision_date.as_deref().and_then(parse_iso8601);

    Some(WasmSshKeyMeta {
        item_id: dc.id.clone(),
        item_name: dc.name.clone(),
        public_key_openssh,
        fingerprint,
        ssh_hosts,
        ssh_user,
        require_confirm,
        revision_date_epoch_secs: revision_date.map(to_epoch_secs),
    })
}

// ── Custom field indexing ────────────────────────────────────────

/// Index custom fields for attribute maps.
///
/// Returns `(key, value)` pairs with proper indexing for duplicate names:
/// - Single occurrence: just `custom.<name>` -> value
/// - Multiple occurrences:
///   - `custom.<name>`   -> first value  (unindexed alias)
///   - `custom.<name>.0` -> first value
///   - `custom.<name>.1` -> second value
///   - `custom.<name>.2` -> third value
///
/// `allowed_types` filters which `field_type` values to include
/// (0 = text, 1 = hidden, 2 = boolean, 3 = linked).
fn index_custom_fields(fields: &[DecryptedField], allowed_types: &[u8]) -> Vec<(String, String)> {
    // Group field values by name, preserving order within each name.
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for field in fields {
        if !allowed_types.contains(&field.field_type) {
            continue;
        }
        if let (Some(name), Some(value)) = (&field.name, &field.value) {
            let name_str = name.as_str();
            let entry = groups.entry(name_str).or_default();
            if entry.is_empty() {
                order.push(name_str);
            }
            entry.push(value.as_str());
        }
    }

    let mut result = Vec::new();
    for name in order {
        let values = &groups[name];
        let base_key = format!("custom.{name}");
        if values.len() == 1 {
            result.push((base_key, values[0].to_string()));
        } else {
            result.push((base_key.clone(), values[0].to_string()));
            for (i, val) in values.iter().enumerate() {
                result.push((format!("{base_key}.{i}"), (*val).to_string()));
            }
        }
    }
    result
}

// ── ISO 8601 parsing ─────────────────────────────────────────────

/// Parse an ISO 8601 timestamp string to `SystemTime`.
///
/// Simple parser: `"2024-01-15T12:30:00.000Z"` — no chrono dependency.
fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let s = s.trim_end_matches('Z');
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_str = parts[1].split('.').next()?;
    let time_parts: Vec<u64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();

    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);
    let (hour, minute, second) = (time_parts[0], time_parts[1], time_parts[2]);

    let days_since_epoch = (year - 1970) * 365
        + (year - 1969) / 4
        + days_before_month(month, is_leap_year(year))
        + (day - 1);

    let secs = days_since_epoch * 86400 + hour * 3600 + minute * 60 + second;

    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_before_month(month: u64, leap: bool) -> u64 {
    let days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let d = days
        .get((month as usize).wrapping_sub(1))
        .copied()
        .unwrap_or(0);
    if leap && month > 2 { d + 1 } else { d }
}

// ═══════════════════════════════════════════════════════════════════
// Auth flow helpers
// ═══════════════════════════════════════════════════════════════════

/// Perform the full authentication + sync flow (synchronous).
///
/// Port of `BitwardenProvider::authenticate`.
fn authenticate(
    config: &GuestConfig,
    password: &str,
    two_factor: Option<TwoFactorSubmission>,
) -> Result<AuthState, BitwardenError> {
    let email = &config.email;
    let api = ApiClient::new(config.urls.clone(), config.device_id.clone());

    // Step 1: Prelogin
    let kdf = api.prelogin(email)?;
    extism_pdk::debug!("got KDF params: {:?}", kdf);

    // Step 2: Key derivation
    let master_key = crypto::derive_master_key(password.as_bytes(), email, &kdf)?;
    let password_hash = crypto::derive_password_hash(&master_key, password.as_bytes());
    let identity_keys = crypto::expand_master_key(&master_key)?;

    // Step 3: Login
    let hash_b64 = crypto::b64_encode(&password_hash);
    let login_resp = api.login_password(email, &hash_b64, two_factor)?;

    let protected_key = login_resp.key.as_deref().ok_or_else(|| {
        BitwardenError::Auth("no protected key in login response".to_string())
    })?;

    // Step 4: Initialize vault state from protected key
    let mut vault_state = VaultState::new(&identity_keys, protected_key)?;

    // Step 5: Sync
    let sync = api.sync(&login_resp.access_token)?;
    vault_state.process_sync(&sync)?;

    Ok(AuthState {
        access_token: login_resp.access_token,
        refresh_token: login_resp.refresh_token,
        vault: vault_state,
    })
}

/// Re-sync the vault using the existing access token.
///
/// If the access token has expired and a refresh token is available,
/// automatically refreshes the token and retries.
///
/// Port of `BitwardenProvider::resync`.
fn resync(auth: &mut AuthState, urls: &ServerUrls, device_id: &str) -> Result<(), BitwardenError> {
    let api = ApiClient::new(urls.clone(), device_id.to_string());

    match api.sync(&auth.access_token) {
        Ok(sync) => {
            auth.vault.process_sync(&sync)?;
            extism_pdk::debug!("vault resynced: ciphers={}", auth.vault.ciphers().len());
            Ok(())
        }
        Err(BitwardenError::Auth(_)) => {
            // Access token expired — try refreshing
            let refresh_token = match &auth.refresh_token {
                Some(rt) => rt.clone(),
                None => {
                    return Err(BitwardenError::Auth(
                        "access token expired and no refresh token available".to_string(),
                    ));
                }
            };

            extism_pdk::debug!("access token expired, refreshing");
            let refresh_resp = api.refresh_token(&refresh_token)?;
            auth.access_token = refresh_resp.access_token;
            if let Some(new_rt) = refresh_resp.refresh_token {
                auth.refresh_token = Some(new_rt);
            }
            extism_pdk::info!("access token refreshed");

            // Retry sync with new token
            let sync = api.sync(&auth.access_token)?;
            auth.vault.process_sync(&sync)?;
            extism_pdk::debug!(
                "vault resynced after token refresh: ciphers={}",
                auth.vault.ciphers().len()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// ── Response builders ────────────────────────────────────────────

/// Build an error `SimpleResponse` from a `BitwardenError`.
fn simple_err(e: &BitwardenError) -> SimpleResponse {
    SimpleResponse {
        ok: false,
        error: Some(e.to_string()),
        error_kind: Some(e.to_error_kind()),
    }
}

/// Build an ok `SimpleResponse`.
fn simple_ok() -> SimpleResponse {
    SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Plugin function exports
// ═══════════════════════════════════════════════════════════════════

/// Return the plugin manifest for discovery.
///
/// Called by the host **before** `init` — no global state is accessed.
/// This allows the host to scan `.wasm` files and discover provider
/// kinds, config requirements, and allowed hosts automatically.
#[plugin_fn]
pub fn plugin_manifest(_: ()) -> FnResult<Json<PluginManifest>> {
    Ok(Json(PluginManifest {
        kind: "bitwarden-pm".to_string(),
        name: "Bitwarden Password Manager".to_string(),
        description: "Bitwarden password manager vault (cloud or self-hosted)".to_string(),
        default_allowed_hosts: vec![
            "*.bitwarden.com".to_string(),
            "*.bitwarden.eu".to_string(),
        ],
        required_options: vec![PluginOptionDescriptor {
            key: "email".to_string(),
            description: "Bitwarden account email".to_string(),
            kind: "text".to_string(),
        }],
        optional_options: vec![
            PluginOptionDescriptor {
                key: "region".to_string(),
                description: "Cloud region: 'us' or 'eu' (default: us)".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "base_url".to_string(),
                description: "Self-hosted base URL, e.g. https://vault.example.com".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "api_url".to_string(),
                description: "Explicit API URL override (overrides region/base_url)".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "identity_url".to_string(),
                description: "Explicit identity URL override (overrides region/base_url)"
                    .to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "collection".to_string(),
                description:
                    "Label stamped on all items as the 'collection' attribute (e.g. 'work')"
                        .to_string(),
                kind: "text".to_string(),
            },
        ],
        id_derivation_key: Some("email".to_string()),
    }))
}

/// Initialise the plugin with provider configuration.
///
/// Called once by the host after loading the WASM module.
/// Expects `InitRequest` JSON with `provider_id`, `provider_name`, and
/// `options` containing `email`, `device_id`, and URL configuration.
#[plugin_fn]
pub fn init(Json(req): Json<InitRequest>) -> FnResult<Json<InitResponse>> {
    let email = req
        .options
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if email.is_empty() {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some("missing required option: email".to_string()),
        }));
    }

    let device_id = req
        .options
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if device_id.is_empty() {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some("missing required option: device_id".to_string()),
        }));
    }

    // Resolve server URLs — same priority as native BitwardenConfig.
    let urls = match (
        req.options.get("api_url").and_then(|v| v.as_str()),
        req.options.get("identity_url").and_then(|v| v.as_str()),
    ) {
        (Some(api), Some(identity)) => ServerUrls {
            api_url: api.to_string(),
            identity_url: identity.to_string(),
        },
        _ => match req.options.get("base_url").and_then(|v| v.as_str()) {
            Some(base) => ServerUrls::from_base(base),
            None => {
                let region = req
                    .options
                    .get("region")
                    .and_then(|v| v.as_str())
                    .unwrap_or("us");
                match region.to_ascii_lowercase().as_str() {
                    "eu" => ServerUrls::official_eu(),
                    _ => ServerUrls::official_us(),
                }
            }
        },
    };

    let config = GuestConfig {
        provider_id: req.provider_id,
        email,
        urls,
        device_id,
    };

    extism_pdk::info!(
        "bitwarden-wasm plugin initialised: provider_id={}",
        config.provider_id
    );

    let mut guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;
    *guard = Some(GuestState {
        config,
        auth: None,
    });

    Ok(Json(InitResponse {
        ok: true,
        error: None,
    }))
}

/// Return the current provider status (locked/unlocked + last sync time).
#[plugin_fn]
pub fn status(_input: ()) -> FnResult<Json<StatusResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        // Not yet initialised — report as locked
        return Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        }));
    };

    match &state.auth {
        Some(auth) => Ok(Json(StatusResponse {
            locked: false,
            last_sync_epoch_secs: auth.vault.last_sync().map(to_epoch_secs),
        })),
        None => Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        })),
    }
}

/// Unlock the vault with a master password (and optional registration fields).
#[plugin_fn]
pub fn unlock(Json(req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
        }));
    };

    // Handle device registration if credentials were supplied
    if let Some(reg_fields) = &req.registration_fields {
        let client_id = reg_fields.get("client_id").map(String::as_str).unwrap_or_default();
        let client_secret = reg_fields.get("client_secret").map(String::as_str).unwrap_or_default();

        if client_id.is_empty() || client_secret.is_empty() {
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some("registration requires client_id and client_secret".to_string()),
                error_kind: Some(ErrorKind::InvalidInput),
            }));
        }

        let api = ApiClient::new(state.config.urls.clone(), state.config.device_id.clone());
        if let Err(e) = api.register_device(&state.config.email, client_id, client_secret) {
            return Ok(Json(simple_err(&e)));
        }
        extism_pdk::info!("device registered for provider '{}'", state.config.provider_id);
    }

    match authenticate(&state.config, &req.password, None) {
        Ok(auth) => {
            let ciphers = auth.vault.ciphers().len();
            state.auth = Some(auth);
            extism_pdk::info!("vault unlocked: ciphers={ciphers}");
            Ok(Json(simple_ok()))
        }
        Err(e) => {
            extism_pdk::warn!("unlock failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// Lock the vault — drop all sensitive state.
#[plugin_fn]
pub fn lock(_input: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    if let Some(state) = guard.as_mut() {
        state.auth = None;
        extism_pdk::info!("vault locked");
    }

    Ok(Json(simple_ok()))
}

/// Re-sync the vault with the Bitwarden server.
#[plugin_fn]
pub fn sync(_input: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
        }));
    };

    let Some(auth) = state.auth.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
        }));
    };

    match resync(auth, &state.config.urls, &state.config.device_id) {
        Ok(()) => Ok(Json(simple_ok())),
        Err(e) => {
            extism_pdk::warn!("sync failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// List all items in the vault.
#[plugin_fn]
pub fn list_items(_input: ()) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            items: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .vault
        .ciphers()
        .iter()
        .map(|dc| cipher_to_wasm_meta(provider_id, dc))
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

/// Search for items matching the given attributes.
#[plugin_fn]
pub fn search(Json(req): Json<SearchRequest>) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            items: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .vault
        .ciphers()
        .iter()
        .filter_map(|dc| {
            let meta = cipher_to_wasm_meta(provider_id, dc);
            if req
                .attributes
                .iter()
                .all(|(key, value)| meta.attributes.get(key) == Some(value))
            {
                Some(meta)
            } else {
                None
            }
        })
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

/// Get full attributes (public + secret names) for a single item.
#[plugin_fn]
pub fn get_item_attributes(Json(req): Json<ItemIdRequest>) -> FnResult<Json<ItemAttributesResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.id) else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let (public, secret_names) = build_item_attributes(&state.config.provider_id, dc);

    Ok(Json(ItemAttributesResponse {
        ok: true,
        error: None,
        error_kind: None,
        public,
        secret_names,
    }))
}

/// Get a specific secret attribute value for an item.
///
/// Returns the secret bytes base64-encoded.
#[plugin_fn]
pub fn get_secret_attr(Json(req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            value_b64: None,
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            value_b64: None,
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.id) else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        }));
    };

    match resolve_secret_attr(dc, &req.attr) {
        Some(bytes) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(Json(SecretAttrResponse {
                ok: true,
                error: None,
                error_kind: None,
                value_b64: Some(b64),
            }))
        }
        None => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("attribute not found: {}", req.attr)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        })),
    }
}

/// List all SSH keys in the vault.
#[plugin_fn]
pub fn list_ssh_keys(_input: ()) -> FnResult<Json<SshKeyListResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SshKeyListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            keys: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SshKeyListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            keys: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let keys: Vec<WasmSshKeyMeta> = auth
        .vault
        .ciphers()
        .iter()
        .filter_map(|dc| cipher_to_ssh_key_meta(provider_id, dc))
        .collect();

    Ok(Json(SshKeyListResponse {
        ok: true,
        error: None,
        error_kind: None,
        keys,
    }))
}

/// Get the PEM-encoded SSH private key for an item.
#[plugin_fn]
pub fn get_ssh_private_key(Json(req): Json<SshPrivateKeyRequest>) -> FnResult<Json<SshPrivateKeyResponse>> {
    let guard = STATE
        .lock()
        .map_err(|e| extism_pdk::Error::msg(format!("state lock poisoned: {e}")))?;

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            pem: None,
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            pem: None,
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.item_id) else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.item_id)),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        }));
    };

    match extract_pem(dc) {
        Some(pem) => Ok(Json(SshPrivateKeyResponse {
            ok: true,
            error: None,
            error_kind: None,
            pem: Some(pem.to_string()),
        })),
        None => Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(format!("no SSH key material found for item: {}", req.item_id)),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        })),
    }
}

/// Return the provider's capabilities.
///
/// Bitwarden PM supports: Sync, Ssh, PasswordChange (NOT Write).
#[plugin_fn]
pub fn capabilities(_input: ()) -> FnResult<Json<CapabilitiesResponse>> {
    Ok(Json(CapabilitiesResponse {
        capabilities: vec![
            "sync".to_string(),
            "ssh".to_string(),
            "password_change".to_string(),
        ],
    }))
}

/// Return the full attribute descriptor catalogue.
#[plugin_fn]
pub fn attribute_descriptors(_input: ()) -> FnResult<Json<AttributeDescriptorsResponse>> {
    Ok(Json(AttributeDescriptorsResponse {
        descriptors: bitwarden_attribute_descriptors(),
    }))
}

/// Return registration info (device registration instructions + fields).
#[plugin_fn]
pub fn registration_info(_input: ()) -> FnResult<Json<RegistrationInfoResponse>> {
    Ok(Json(RegistrationInfoResponse {
        has_registration: true,
        instructions: Some(
            "This device is not registered with Bitwarden. To register it, you need \
             your personal API key.\n\n\
             Find it at: Bitwarden web vault \u{2192} Account Settings \u{2192} Security \u{2192} Keys \u{2192} View API Key"
                .to_string(),
        ),
        fields: vec![
            WasmAuthField {
                id: "client_id".to_string(),
                label: "API key client_id".to_string(),
                placeholder: "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".to_string(),
                required: true,
                kind: "text".to_string(),
            },
            WasmAuthField {
                id: "client_secret".to_string(),
                label: "API key client_secret".to_string(),
                placeholder: String::new(),
                required: true,
                kind: "secret".to_string(),
            },
        ],
    }))
}

/// Return the auth fields for this provider (just the master password).
#[plugin_fn]
pub fn auth_fields(_input: ()) -> FnResult<Json<AuthFieldsResponse>> {
    Ok(Json(AuthFieldsResponse {
        fields: vec![WasmAuthField {
            id: "password".to_string(),
            label: "Master Password".to_string(),
            placeholder: "Enter your Bitwarden master password".to_string(),
            required: true,
            kind: "password".to_string(),
        }],
    }))
}
