# Canonical Secrets, Credentials, Wallet & Keyring Storage Filenames — A Detection Reference for Ensign

> **Update (Nov 2026):** how Ensign *uses* these patterns has changed since this was written. It no longer suggests `setfacl` commands or reclassifies permission-denied errors: clamd now receives an open file handle from Ensign instead of opening files itself. A HIGH-confidence match is now skipped before it's opened (no hash, no scan), except for executables and the watched SSH files (`authorized_keys`, `~/.ssh/config`, `~/.ssh/rc`). See "How clamd Reads Your Files" in the README. The sourcing below still defines the pattern lists themselves.

## TL;DR
- This report catalogs ~70 high-confidence, real-world filenames, directory names, and extensions used by SSH, GPG, cryptocurrency wallets, password managers, cloud CLIs, container tooling, browsers, and shell/environment secret conventions — split into **exact fixed strings** (safe to match with string equality: `id_rsa`, `wallet.dat`, `pubring.kbx`, `credentials`, `config.json`, `.vault-token`, etc.) and **naming conventions/prefixes** (require pattern matching: Ethereum `UTC--*` keystore files, `*.kdbx`, `*.keys`, `*.seco`, `*.ppk`).
- For Ensign's two use cases, a path is treated as a likely sensitive store when it matches an exact fixed directory (`.ssh/`, `.gnupg/`, `.aws/`, `.gnupg/private-keys-v1.d/`), an exact fixed filename, or a strongly-scoped extension/prefix — and, on those paths, `setfacl` suggestions are suppressed and permission-denied errors are reclassified as benign.
- Low-precision traps exist here: the bare words "wallet"/"secrets" are unreliable on their own; `.env`, `.der`, `.cer`, `.crt`, and `config` are looser patterns that need directory context (e.g., `.ssh/config`, `.kube/config`, `.docker/config.json`) to avoid false positives.

## Key Findings
1. **The highest-precision signals are directory names, not filenames.** `~/.ssh/`, `~/.gnupg/` (and its `private-keys-v1.d/` subdirectory), `~/.aws/`, `~/.azure/`, `~/.password-store/`, and `~/.electrum/wallets/` are canonical, documented, and rarely collide with unrelated content. Matching on the directory is more robust than matching individual files inside it.
2. **Several credential files are fixed, universal names** appearing identically across all platforms: `wallet.dat` (Bitcoin Core), `credentials` and `config` (AWS, inside `.aws/`), `config.json` (Docker, inside `.docker/`), `config` (kubeconfig, inside `.kube/`), `application_default_credentials.json` and `credentials.db` (gcloud), `data.json` (Bitwarden desktop), `app.json` (Ledger Live), `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `.vault-token`.
3. **Cryptocurrency wallets are the most format-diverse category** and require both exact names and prefix/extension matching. Bitcoin Core uses fixed `wallet.dat`; Ethereum/geth uses the `UTC--<ISO8601-timestamp>--<address>` prefix convention with no extension; Monero uses a `*.keys` extension plus companion `*.address.txt`; Electrum defaults to a file literally named `default_wallet` (no extension); Exodus uses `*.seco` files (notably `seed.seco`) inside an `exodus.wallet` folder.
4. **Browser-extension wallets (MetaMask) do not use fixed filenames** — the encrypted vault lives inside the browser's generic extension storage (Chromium `Local Extension Settings` LevelDB `.ldb`/`.log` files; Firefox IndexedDB under `storage/default/moz-extension+…`). These are impractical to target by filename and are largely out of scope for a path-based scanner.
5. **Version/legacy splits matter.** GnuPG changed from `secring.gpg`/`pubring.gpg` (pre-2.1) to `private-keys-v1.d/` + `pubring.kbx` (2.1+); KeePass uses `.kdb` (v1.x) vs `.kdbx` (v2.x); Bitcoin Core moved from a single `wallet.dat` in the datadir root to per-wallet folders under a `wallets/` subdirectory; Azure CLI, starting with version 2.30.0, adopted MSAL and no longer generates `accessTokens.json`, replacing it with `msal_token_cache.bin`. Both old and new names show up on real systems, so detection needs to account for each.

## Details

### 1. SSH keys (OpenSSH)
The canonical location is the `~/.ssh/` directory. OpenSSH searches for default private-key names based on algorithm, per Oracle/Red Hat/Wikibooks documentation.

**Fixed filenames (private keys — highest sensitivity):**
- `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` — default private keys. `.pub` counterparts are public (lower sensitivity but conventionally paired). DSA (`id_dsa`) support was removed in OpenSSH 10.0, released 2025-04-09; per the official release notes, "This release removes support for the weak DSA signature algorithm, completing the deprecation process that began in 2015 (when DSA was disabled by default)" — but `id_dsa` files still persist on legacy systems.
- `id_ed25519_sk`, `id_ecdsa_sk` — FIDO/U2F-backed keys (OpenSSH 8.2+).
- `identity` — legacy SSH1 RSA private key (very old systems).
- Host keys (usually under `/etc/ssh/`): `ssh_host_rsa_key`, `ssh_host_ecdsa_key`, `ssh_host_ed25519_key`, `ssh_host_dsa_key`, and legacy `ssh_host_key` — these are private host keys.

**Fixed filenames (config/state):**
- `authorized_keys` — server-side list of permitted public keys.
- `known_hosts` — client-side cache of server host keys.
- `config` — per-host client configuration (only sensitive in `.ssh/` context).

**Convention:** Users may name keys anything (e.g., `id_ed25519_work`), so `~/.ssh/id_*` is a useful prefix pattern; the whole `~/.ssh/` directory is the most reliable target. `/etc/ssh/ssh_host_*_key` is a good host-key pattern.

### 2. GPG / PGP keyrings (GnuPG)
Canonical directory: `~/.gnupg/` (overridable via `GNUPGHOME`). Per the official GnuPG manual and multiple references:

**Fixed names (modern, GnuPG 2.1+):**
- `private-keys-v1.d/` — **directory** holding individual private keys as `<keygrip>.key` files. This is the single most sensitive GnuPG location.
- `pubring.kbx` — public keyring in the newer keybox format (shared with gpgsm).
- `trustdb.gpg` — trust database.
- `openpgp-revocs.d/` — pre-generated revocation certificates (filename = key fingerprint).

**Fixed names (legacy, pre-2.1 — still on real systems):**
- `secring.gpg` — legacy secret keyring (private keys). GnuPG 1.4 always uses this.
- `pubring.gpg` — legacy public keyring.
- `trustedkeys.gpg` / `trustedkeys.kbx` — default gpgv keyrings.

**Standalone exported key files (conventions, appear anywhere):**
- `.asc` — ASCII-armored key/signature/message (can be a private key export).
- `.gpg`, `.pgp` — binary OpenPGP data (can hold private keys or encrypted data).
- `.sig`, `.sign` — detached signatures (not secret, but OpenPGP-related).

Note `.asc`/`.gpg`/`.pgp` are broad — they can be public keys, signatures, or encrypted files, not necessarily private key material. Directory context (`~/.gnupg/`) raises confidence sharply.

### 3. Cryptocurrency wallets

**Bitcoin Core — fixed `wallet.dat`.** Default data directories: Linux `~/.bitcoin/`, Windows `%APPDATA%\Bitcoin\`, macOS `~/Library/Application Support/Bitcoin/`. Historically `wallet.dat` lived directly in the datadir root; per the official `bitcoin/doc/managing-wallets.md`, wallets are now created in a `wallets/` subfolder of the datadir (overridable with `-walletdir`). `wallet.dat` is not encrypted by default. Bitcoin-forked coins reuse the same `wallet.dat` name in their own datadirs (e.g., `~/.litecoin/`, `~/.dogecoin/`).

**Ethereum (geth / Mist / MyEtherWallet exports) — `UTC--<timestamp>--<address>` prefix convention, no extension.** Each account is a Web3 Secret Storage V3 JSON keystore file named `UTC--<ISO8601 created-at>--<40-hex-char address>` (e.g., `UTC--2015-08-11T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b`). Stored in a `keystore/` subdirectory. Default locations: Linux `~/.ethereum/keystore/`, macOS `~/Library/Ethereum/keystore/`, Windows `%APPDATA%\Ethereum\keystore\`. The `keystore/` directory name and the `UTC--*` prefix are both strong signals. Parity/OpenEthereum and many others reuse the V3 format.

**Electrum — fixed default name `default_wallet` (no extension).** Per official Electrum docs, the default wallet file is literally `default_wallet`, created in the `wallets/` subfolder of the Electrum datadir. Datadir: Linux and macOS both use `~/.electrum/` (note: macOS uses the dotfolder, NOT `~/Library/Application Support/`); Windows uses `%APPDATA%\Electrum\`. So default paths are `~/.electrum/wallets/default_wallet` (Linux/macOS) and `%APPDATA%\Electrum\wallets\default_wallet` (Windows). Wallet-file encryption using ECIES has been activated by default since version 2.8 (Release 2.8.0, March 9, 2017), per Electrum's official FAQ. Users may name additional wallets arbitrarily, so the `wallets/` directory under the Electrum datadir is the reliable target.

**Monero — `*.keys` extension convention.** `monero-wallet-cli` creates a wallet as a set of files with a user-chosen base name: `<name>` (cache), `<name>.keys` (the encrypted key file — the critical one), and `<name>.address.txt`. Per official Monero docs, the `.keys` file is required for full restore. There is no fixed base name, so `*.keys` (paired with a `*.address.txt` sibling) is the pattern.

**Exodus — `*.seco` files in an `exodus.wallet` folder.** Desktop Exodus stores Secure EXODUS Containers: `seed.seco`, `info.seco`, `storage.seco`, `twofactor.seco`, `twofactor-secret.seco` (and sometimes `passphrase.json`) inside an `exodus.wallet` directory. Locations: Windows `%APPDATA%\Exodus\`, macOS `~/Library/Application Support/Exodus/`. The browser-extension version stores fragments in a Chromium extension folder (`aholpfdialjgjfhomihkjbmgjidlcdno`) as `.ldb`/`.log`. `seed.seco` is the crown-jewel file; the `exodus.wallet` folder and `*.seco` extension are reliable targets.

**MetaMask — no fixed filename (browser-extension vault).** The encrypted vault is a JSON blob encrypted with AES-256-GCM using a key derived via PBKDF2-HMAC-SHA256 (historically 10,000 iterations, raised to 600,000 iterations in newer versions per MetaMask's browser-passworder implementation); the JSON storing salt, IV, ciphertext and GCM tag is written to `chrome.storage.local` on Chromium (under `…/Local Extension Settings/<extension-id>/` as LevelDB `.ldb`/`.log` files) or IndexedDB on Firefox (`storage/default/moz-extension+…/idb/…`, backed by SQLite). The Chromium extension ID is `nkbihfbeogaeaoehlefnkodbefgpgknn`; the Firefox extension ID is `webextension@metamask.io` (with a per-install UUID). Not practical to match by filename; effectively out of scope for a path-based scanner beyond flagging browser profile directories.

**Hardware-wallet companion apps — metadata only, NOT private-key stores.** Hardware-wallet private keys never leave the device. Ledger Live stores a fixed-name `app.json` (settings, accounts, xpubs/balances) in its Electron `userData` folder: Windows `%APPDATA%\Ledger Live\app.json`, macOS `~/Library/Application Support/Ledger Live/app.json`, Linux `~/.config/Ledger Live/app.json`. Trezor Suite stores encrypted labels/metadata (no seed, no keys) under a `@trezor/suite-desktop/metadata/` folder (macOS `~/Library/Application Support/@trezor/suite-desktop/metadata/`, Windows `%APPDATA%\@trezor\suite-desktop\metadata`, Linux `~/.config/@trezor/suite-desktop`), with per-account hashed filenames (no single canonical name). Treat these as privacy-sensitive but lower-priority than actual key stores.

### 4. Password managers
- **KeePass / KeePassXC:** `.kdbx` (KeePass 2.x, introduced 2007/2008, XML-based, AES/ChaCha20) and legacy `.kdb` (KeePass 1.x, C++ proprietary format). Both begin with File Signature 1 `0x9AA2D903`; Signature 2 distinguishes the format — `0xB54BFB65` for `.kdb` (KeePass 1.x) and `0xB54BFB67` for released `.kdbx` (KeePass 2.x), per the KeePass source (`KdbxFile.cs`) and the official KDBX File Format Specification. `.kdbx` is by far the most common; both are strong extension signals. Also read by KeePassXC, KeePassDX, KeeWeb, Strongbox.
- **1Password:** `.opvault` — legacy local vault, actually a **directory** (bundle) named e.g. `1Password.opvault` containing `default/band_*.js` and `profile.js` files. `.1pux` — the modern 1Password export archive (a zip). `.1pif` — older interchange export format. `.agilekeychain` — the oldest local vault bundle format. All are strong 1Password-specific signals.
- **Bitwarden:** desktop app stores its (encrypted) local vault in a fixed-name `data.json`. Locations follow the Electron pattern (Windows `%APPDATA%\Bitwarden\`, macOS `~/Library/Application Support/Bitwarden/`, Linux `~/.config/Bitwarden/`). The Directory Connector also uses a `data.json`.
- **pass (password-store):** `~/.password-store/` directory (overridable via `PASSWORD_STORE_DIR`), containing one `<name>.gpg` GnuPG-encrypted file per entry organized in subfolders, plus a `.gpg-id` file naming the encryption key. The `~/.password-store/` directory is the reliable target.

### 5. Cloud provider credential files
- **AWS:** `~/.aws/credentials` (access keys, INI format) and `~/.aws/config`. Overridable via `AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE`. The `.aws/` directory plus fixed `credentials` filename is a top signal.
- **Azure CLI:** `~/.azure/` directory. Legacy (ADAL, pre-2.30) `accessTokens.json` + `azureProfile.json`. Modern (MSAL) `msal_token_cache.bin` (encrypted on Windows via DPAPI; plaintext on Linux/macOS) + `azureProfile.json`. Per Microsoft Learn ("MSAL-based Azure CLI"), "Starting with version 2.30.0, Azure CLI uses Microsoft Authentication Library (MSAL)… The latest versions of the Azure CLI use MSAL and no longer generate accessTokens.json." Azure PowerShell uses `AzureRmContext.json` / `TokenCache.dat`.
- **Google Cloud (gcloud):** config dir `~/.config/gcloud/` (Windows `%APPDATA%\gcloud\`). Files: `application_default_credentials.json` (ADC, user refresh token in cleartext JSON), `credentials.db` (SQLite store of gcloud's own OAuth tokens), `access_tokens.db` (cached access tokens), and the `legacy_credentials/` directory containing per-account `adc.json` cleartext credentials. All fixed names — high signal.
- Other CLIs commonly seen: `~/.config/doctl/` (DigitalOcean), `~/.oci/` (Oracle Cloud), `~/.config/gh/hosts.yml` (GitHub CLI token), `~/.databrickscfg`, `~/.config/openstack/clouds.yaml`.

### 6. Container / orchestration tooling
- **Docker:** `~/.docker/config.json` — contains base64-encoded (NOT encrypted) registry credentials in the `auths` field unless a credential helper (`credsStore`, e.g., `osxkeychain`) is used. Fixed name in `.docker/` context.
- **Kubernetes:** `~/.kube/config` — the default kubeconfig (YAML with cluster certs, tokens, and client keys). Overridable via `KUBECONFIG` or `--kubeconfig`. Fixed name in `.kube/` context.
- **Related:** `/var/run/secrets/kubernetes.io/serviceaccount/token` (in-pod service-account token), `/etc/rancher/k3s/k3s.yaml` (k3s admin kubeconfig), Helm `repositories.yaml`, and podman's auth file (`${XDG_RUNTIME_DIR}/containers/auth.json`).

### 7. Browser-stored credentials (context; largely out of scope)
- **Chromium (Chrome, Edge, Brave):** SQLite database literally named `Login Data` (in the profile's `Default/` folder), `logins` table; encryption key in the `Local State` JSON file (DPAPI-wrapped on Windows). Cookies in `Cookies` / `Network/Cookies`. Older Chrome used `Web Data`.
- **Firefox:** `logins.json` (encrypted logins) paired with `key4.db` (the decryption key database; older `key3.db`), in the profile folder. `cert9.db` for certs.
These are fixed names but sit inside browser profile directories; a file scanner may note them but they are secondary to the primary credential stores above.

### 8. Shell / environment secrets conventions
- `.netrc` (and Windows `_netrc`) — **plaintext** credentials for FTP/HTTP/Git auth; consumed by curl, git, pip, etc. Fixed name. High signal.
- `.git-credentials` (also `~/.config/git/credentials`) — git credential store, plaintext URLs with embedded passwords/tokens. Fixed name.
- `.npmrc` (user `~/.npmrc` or project `.npmrc`) — can contain `_authToken` npm registry tokens.
- `.pypirc` — PyPI upload credentials.
- `.yarnrc` / `.yarnrc.yml` — can contain registry tokens.
- `.env` (and `.env.local`, `.env.production`, etc.) — **very common but generic** convention for environment-variable secrets. Flag as low-precision: matches many non-secret uses; treat as a weaker signal requiring corroboration.
- `.pgpass` (PostgreSQL), `.my.cnf` (MySQL client credentials), `.boto` (legacy AWS/GCS), `.s3cfg` (s3cmd) — additional fixed-name credential files.

### 9. Other well-established high-confidence conventions
- **HashiCorp Vault:** `~/.vault-token` — fixed name, stores the Vault auth token in plaintext after `vault login`.
- **PuTTY:** `.ppk` ("PuTTY Private Key") — fixed proprietary format holding a private (and public) key; generated by PuTTYgen, used by PuTTY/Pageant/Plink. MIME `application/x-putty-private-key`. Strong private-key signal.
- **Generic TLS/PKI key & cert extensions (conventions, not guarantees):**
  - Can contain **private keys** (treat as sensitive): `.pem`, `.key`, `.p12`, `.pfx` (both PKCS#12; "the only file format that can be used to export a certificate and its private key"). `.jks` / `.keystore` (Java KeyStore) and `.bks` also hold keys.
  - Usually **public certificates only** (lower priority): `.crt`, `.cer`, `.der`. Caveat: extension does not guarantee content — a `.pem` can hold a key regardless of name, and DER encoding can technically carry key material; content inspection (`-----BEGIN … PRIVATE KEY-----` headers or PKCS#12 magic bytes) is the authoritative signal.
- **Kerberos:** `krb5.keytab` / `*.keytab` and credential caches `/tmp/krb5cc_*` — service keys and ticket caches.
- **WireGuard:** `/etc/wireguard/*.conf` with embedded `PrivateKey =`.
- **Ansible Vault:** files beginning with the header `$ANSIBLE_VAULT;` (content signature rather than fixed name).

## Consolidated pattern tables

### A. Exact fixed strings (safe for string-equality matching)

**Fixed directories (match directory + contents):**
`.ssh/`, `.gnupg/`, `.gnupg/private-keys-v1.d/`, `.gnupg/openpgp-revocs.d/`, `.aws/`, `.azure/`, `.config/gcloud/`, `.config/gcloud/legacy_credentials/`, `.docker/`, `.kube/`, `.password-store/`, `.electrum/wallets/`, `.ethereum/keystore/`, `.bitcoin/` (+ forks), `exodus.wallet/`, `Ledger Live/`, `@trezor/suite-desktop/metadata/`.

**Fixed filenames:**
`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `id_ed25519_sk`, `id_ecdsa_sk`, `identity`, `authorized_keys`, `known_hosts`, `pubring.kbx`, `pubring.gpg`, `secring.gpg`, `trustdb.gpg`, `trustedkeys.gpg`, `trustedkeys.kbx`, `wallet.dat`, `default_wallet`, `application_default_credentials.json`, `credentials.db`, `access_tokens.db`, `adc.json`, `accessTokens.json`, `azureProfile.json`, `msal_token_cache.bin`, `credentials` (in `.aws/`), `config` (in `.ssh/` or `.kube/`), `config.json` (in `.docker/`), `data.json` (in Bitwarden dir), `app.json` (in Ledger Live dir), `seed.seco`, `info.seco`, `storage.seco`, `.netrc`, `_netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `.vault-token`, `.pgpass`, `.my.cnf`, `.s3cfg`, `.boto`, `.gpg-id`, `Login Data`, `logins.json`, `key4.db`, `key3.db`, `krb5.keytab`.

### B. Naming conventions / prefixes / extensions (require pattern matching)

| Pattern | Ecosystem | Type | Scoping for precision |
|---|---|---|---|
| `UTC--*` | Ethereum keystore V3 | file prefix, no ext | require parent `keystore/` |
| `*.keys` + `*.address.txt` | Monero | extension pair | pair or Monero datadir |
| `*.seco` | Exodus | extension | safe standalone |
| `*.kdbx`, `*.kdb` | KeePass 2.x / 1.x | extension | safe standalone |
| `*.opvault`, `*.1pux`, `*.1pif`, `*.agilekeychain` | 1Password | ext / bundle | safe standalone |
| `*.ppk` | PuTTY | extension | safe standalone |
| `*.keytab` | Kerberos | extension | safe standalone |
| `id_*` | OpenSSH | file prefix | require `.ssh/` |
| `ssh_host_*_key` | OpenSSH host keys | file pattern | require `/etc/ssh/` |
| `*.gpg` | GnuPG / pass | extension | require `.password-store/` or `.gnupg/` for high conf |
| `*.asc`, `*.pgp` | OpenPGP | extension | medium conf (may be public/signature) |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` | TLS/PKI | extension | medium-high (may bear private key) |
| `*.crt`, `*.cer`, `*.der` | TLS/PKI | extension | low (usually public cert) |
| `.env*` | generic env secrets | file prefix | low; require corroboration |

## How Ensign Applies This

**HIGH confidence (implemented).** A path is treated as a sensitive credentials store — `setfacl` suggestions suppressed, permission-denied errors reclassified as expected — when it matches any fixed directory (Table A) or fixed filename (Table A), with scoped filenames requiring their expected parent directory to further cut collisions.

**MEDIUM confidence (implemented).** The distinctive standalone extensions (`*.kdbx`, `*.kdb`, `*.seco`, `*.opvault`, `*.1pux`, `*.ppk`, `*.keytab`) are matched directly; the ambiguous ones are gated by directory/pairing scope (`UTC--*` inside `keystore/`; `*.keys` paired with `*.address.txt`; `*.gpg` inside `.password-store/`/`.gnupg/`; `id_*` inside `.ssh/`). `.p12`/`.pfx`/`.pem`/`.key`/`.jks`/`.keystore` sit at this tier as private-key-bearing at medium-high confidence.

**NONE — deliberately excluded.** `.env*`, bare `.crt`/`.cer`/`.der`, bare `config`, and any match on the English words "wallet"/"secret"/"key" in arbitrary path components are treated as low-precision and left unflagged unless paired with a stronger signal (e.g., residing inside a known credential directory).

**Benchmarks that would change the guidance:**
- If false-positive telemetry shows `.pem`/`.key`/`.env` matching non-secret files (build artifacts, sample data), demote them from Stage 2 to Stage 3 (content-inspection-gated).
- If you gain cheap file-content/magic-byte reads, promote content-signature detection (PEM `BEGIN PRIVATE KEY`; KDBX/KDB File Signature 1 `0x9AA2D903`; PKCS#12 magic; `$ANSIBLE_VAULT;`) above extension heuristics.
- Track OpenSSH/GnuPG/Bitcoin/Azure version drift; when legacy names (`id_dsa`, `secring.gpg`, root-datadir `wallet.dat`, `accessTokens.json`) stop appearing in scanned fleets they can be deprioritized — but not removed, since old systems persist.

## Caveats
- **Extensions never guarantee content.** `.pem`, `.der`, `.crt`, `.cer`, `.key`, `.gpg`, `.asc` describe an encoding/format, not whether private key material is present. A `.crt` usually holds only a public certificate, but a `.pem` with any name can hold a private key. Where feasible, confirm with content inspection rather than relying on the extension alone.
- **User overrides break path assumptions.** Nearly every tool allows relocating its store (`GNUPGHOME`, `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`, `PASSWORD_STORE_DIR`, `-walletdir`, `--datadir`, `GOOGLE_APPLICATION_CREDENTIALS`). Directory-based detection will miss relocated stores; filename/extension detection helps recover some of these.
- **Legacy vs modern coexist on real systems.** GnuPG (`secring.gpg` vs `private-keys-v1.d/`), KeePass (`.kdb` vs `.kdbx`), Bitcoin Core (datadir-root vs `wallets/` subdir), Azure CLI (`accessTokens.json` vs `msal_token_cache.bin`). Keep both.
- **Browser-extension wallets and browser password stores are hard to target by path** because the secrets live inside generic profile/extension storage (LevelDB, IndexedDB, SQLite) with opaque or ID-based filenames. MetaMask in particular has no stable filename. These are noted for completeness but are secondary priorities for a path-based scanner.
- **Companion apps for hardware wallets are not key stores.** Ledger Live (`app.json`) and Trezor Suite metadata hold settings, xpubs, and labels — privacy-sensitive but not private keys, which remain on-device — lower priority than actual key stores.
- **Some sourcing is community/vendor-tier.** Exact per-OS paths for Exodus, Trezor Suite metadata, and some browser artifacts draw partly on vendor guides, recovery-service write-ups, and staff-confirmed forum posts rather than first-party spec documents; the filenames/extensions themselves are well-corroborated, but exact directory paths can vary by app version.
- **Bitcoin Core `wallet.dat` is unencrypted by default**, and Docker `config.json` stores only base64-encoded (not encrypted) registry credentials — both are especially high-value to protect, reinforcing why `setfacl` auto-suggestions on them should be suppressed.