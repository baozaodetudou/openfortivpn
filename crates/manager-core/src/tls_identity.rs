//! Durable, paired HTTPS identities shared by the desktop and headless hosts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
struct Identity {
    #[serde(default = "managed_default")]
    managed: bool,
    bind_address: String,
    certificate_sha256: String,
    key_sha256: String,
}
fn managed_default() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
struct Transaction {
    certificate: String,
    private_key: String,
    identity: Identity,
}
impl Drop for Transaction {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

fn invalid() -> io::Error {
    io::Error::other("HTTPS identity is invalid, mismatched or does not cover the bind address")
}

fn validate(certificate: &[u8], key: &[u8], bind: &str) -> io::Result<()> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
    let cert = CertificateDer::from_pem_slice(certificate).map_err(|_| invalid())?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| invalid())?;
    rustls::sign::CertifiedKey::from_der(
        vec![cert.clone()],
        key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|_| invalid())?;
    let server = ServerName::try_from(bind.to_string()).map_err(|_| invalid())?;
    webpki::EndEntityCert::try_from(&cert)
        .map_err(|_| invalid())?
        .verify_is_valid_for_subject_name(&server)
        .map_err(|_| invalid())
}
fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

pub struct TlsIdentityStore {
    directory: PathBuf,
}
impl TlsIdentityStore {
    /// The caller owns a private directory. Files and journals are written with
    /// mode 0600 or an explicit protected Windows DACL.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
    pub fn ensure(&self, bind: &str) -> io::Result<(PathBuf, PathBuf)> {
        self.ensure_with(bind, crate::atomic_file::write_private)
    }

    fn ensure_with(
        &self,
        bind: &str,
        mut write: impl FnMut(&Path, &[u8]) -> io::Result<()>,
    ) -> io::Result<(PathBuf, PathBuf)> {
        crate::private_file::verify_directory(&self.directory)?;
        let _lock = crate::private_file::lock(&self.directory.join(".tls.lock"))?;
        let cert = self.directory.join("certificate.pem");
        let key = self.directory.join("private-key.pem");
        let manifest = self.directory.join(".tls-identity.json");
        let pending = self.directory.join(".tls-transaction.json");
        if pending.try_exists()? {
            let bytes = Zeroizing::new(crate::private_file::read(&pending, 1024 * 1024)?);
            let transaction: Transaction = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            validate(
                transaction.certificate.as_bytes(),
                transaction.private_key.as_bytes(),
                &transaction.identity.bind_address,
            )?;
            if hash(transaction.certificate.as_bytes()) != transaction.identity.certificate_sha256
                || hash(transaction.private_key.as_bytes()) != transaction.identity.key_sha256
            {
                return Err(invalid());
            }
            self.commit(&transaction, &cert, &key, &manifest, &pending, &mut write)?;
        }
        if cert.try_exists()? && key.try_exists()? {
            let certificate = crate::private_file::read(&cert, 1024 * 1024)?;
            let private_key = Zeroizing::new(crate::private_file::read(&key, 1024 * 1024)?);
            let existing: Option<Identity> = if manifest.try_exists()? {
                Some(
                    serde_json::from_slice(&crate::private_file::read(&manifest, 16 * 1024)?)
                        .map_err(|_| invalid())?,
                )
            } else {
                None
            };
            let unchanged = existing.as_ref().is_some_and(|identity| {
                identity.certificate_sha256 == hash(&certificate)
                    && identity.key_sha256 == hash(&private_key)
            });
            let regenerate = unchanged
                && existing
                    .as_ref()
                    .is_some_and(|identity| identity.managed && identity.bind_address != bind);
            if !regenerate {
                validate(&certificate, &private_key, bind)?;
                let identity = Identity {
                    managed: unchanged && existing.is_some_and(|identity| identity.managed),
                    bind_address: bind.into(),
                    certificate_sha256: hash(&certificate),
                    key_sha256: hash(&private_key),
                };
                write(
                    &manifest,
                    &serde_json::to_vec_pretty(&identity).map_err(io::Error::other)?,
                )?;
                return Ok((cert, key));
            }
        } else if cert.try_exists()? || key.try_exists()? {
            return Err(io::Error::other(
                "HTTPS identity is incomplete; install a matching certificate and key",
            ));
        }
        let mut names = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        if !names.iter().any(|name| name == bind) {
            names.push(bind.to_string());
        }
        let generated = rcgen::generate_simple_self_signed(names).map_err(|_| invalid())?;
        let certificate = generated.cert.pem();
        let private_key = generated.signing_key.serialize_pem();
        let transaction = Transaction {
            identity: Identity {
                managed: true,
                bind_address: bind.into(),
                certificate_sha256: hash(certificate.as_bytes()),
                key_sha256: hash(private_key.as_bytes()),
            },
            certificate,
            private_key,
        };
        validate(
            transaction.certificate.as_bytes(),
            transaction.private_key.as_bytes(),
            bind,
        )?;
        let bytes =
            Zeroizing::new(serde_json::to_vec_pretty(&transaction).map_err(io::Error::other)?);
        write(&pending, &bytes)?;
        self.commit(&transaction, &cert, &key, &manifest, &pending, &mut write)?;
        Ok((cert, key))
    }

    fn commit(
        &self,
        transaction: &Transaction,
        cert: &Path,
        key: &Path,
        manifest: &Path,
        pending: &Path,
        write: &mut impl FnMut(&Path, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        write(key, transaction.private_key.as_bytes())?;
        write(cert, transaction.certificate.as_bytes())?;
        write(
            manifest,
            &serde_json::to_vec_pretty(&transaction.identity).map_err(io::Error::other)?,
        )?;
        fs::remove_file(pending)?;
        #[cfg(unix)]
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private_directory() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
    #[test]
    fn interruption_at_each_write_recovers_the_complete_pair() {
        for fail_at in 1..=4 {
            let root = private_directory();
            let store = TlsIdentityStore::new(root.path());
            let mut writes = 0;
            assert!(store
                .ensure_with("192.0.2.1", |path, bytes| {
                    writes += 1;
                    if writes == fail_at {
                        return Err(io::Error::other("injected disk failure"));
                    }
                    crate::atomic_file::write_private(path, bytes)
                })
                .is_err());
            let (cert, key) = store.ensure("192.0.2.1").unwrap();
            validate(
                &fs::read(cert).unwrap(),
                &fs::read(key).unwrap(),
                "192.0.2.1",
            )
            .unwrap();
            assert!(!root.path().join(".tls-transaction.json").exists());
        }
    }
    #[test]
    fn operator_identity_is_preserved_and_invalid_replacement_is_rejected() {
        let root = private_directory();
        let custom = rcgen::generate_simple_self_signed(vec!["192.0.2.7".into()]).unwrap();
        let cert = root.path().join("certificate.pem");
        let key = root.path().join("private-key.pem");
        crate::atomic_file::write_private(&cert, custom.cert.pem().as_bytes()).unwrap();
        crate::atomic_file::write_private(&key, custom.signing_key.serialize_pem().as_bytes())
            .unwrap();
        let store = TlsIdentityStore::new(root.path());
        store.ensure("192.0.2.7").unwrap();
        assert!(store.ensure("192.0.2.8").is_err());
        assert_eq!(fs::read_to_string(&cert).unwrap(), custom.cert.pem());
        let other = rcgen::generate_simple_self_signed(vec!["192.0.2.7".into()]).unwrap();
        crate::atomic_file::write_private(&key, other.signing_key.serialize_pem().as_bytes())
            .unwrap();
        assert!(store.ensure("192.0.2.7").is_err());
        assert_eq!(fs::read_to_string(&cert).unwrap(), custom.cert.pem());
    }
    #[test]
    fn managed_ipv6_bind_change_regenerates_and_symlinked_key_is_not_read() {
        let root = private_directory();
        let store = TlsIdentityStore::new(root.path());
        let (cert, _key) = store.ensure("127.0.0.1").unwrap();
        let original = fs::read(&cert).unwrap();
        store.ensure("2001:db8::1").unwrap();
        assert_ne!(original, fs::read(&cert).unwrap());
        #[cfg(unix)]
        {
            fs::rename(&_key, root.path().join("actual-key")).unwrap();
            std::os::unix::fs::symlink(root.path().join("actual-key"), &_key).unwrap();
            assert!(store.ensure("2001:db8::1").is_err());
        }
    }
}
