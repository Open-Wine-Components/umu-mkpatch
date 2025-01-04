use pyo3::prelude::*;
use ssh_key::{HashAlg, PrivateKey, PublicKey, SshSig};
use std::io::{self};

/// Required parameter to create/verify digital signatures
/// See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD
const NAMESPACE: &str = "umu.openwinecomponents.org";

#[pyfunction]
fn ssh_sign(source: &[u8], message: &[u8]) -> io::Result<String> {
    let private_key = PrivateKey::from_openssh(source).unwrap();
    let signature = private_key
        .sign(NAMESPACE, HashAlg::Sha512, message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    signature
        .to_pem(ssh_key::LineEnding::LF)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

#[pyfunction]
fn ssh_verify(source: &str, message: &[u8], pem: &[u8]) -> io::Result<()> {
    let public_key = PublicKey::from_openssh(source)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let ssh_sig = SshSig::from_pem(pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    public_key
        .verify(NAMESPACE, message, &ssh_sig)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(())
}

#[pymodule(name = "umu_mkpatch")]
fn umu(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ssh_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ssh_verify, m)?)?;
    Ok(())
}
