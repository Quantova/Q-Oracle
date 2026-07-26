// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::sync::atomic::{compiler_fence, Ordering};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey, Signature, SEED_BYTES};

fn secure_wipe(bytes: &mut [u8]) {
    for slot in bytes.iter_mut() {
        *slot = 0;
    }
    compiler_fence(Ordering::SeqCst);
    let _ = core::hint::black_box(&*bytes);
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

struct ZeroizingSecretKey {
    bytes: SecretKey,
}

impl ZeroizingSecretKey {
    fn new(bytes: SecretKey) -> ZeroizingSecretKey {
        ZeroizingSecretKey { bytes }
    }

    fn expose(&self) -> &SecretKey {
        &self.bytes
    }

    #[cfg(test)]
    fn clear_for_test(&mut self) {
        secure_wipe(&mut self.bytes);
    }
}

impl Drop for ZeroizingSecretKey {
    fn drop(&mut self) {
        secure_wipe(&mut self.bytes);
    }
}

pub trait AttestationSigner {
    fn operator_id(&self) -> u32;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8], context: &[u8]) -> Signature;
}

pub struct SoftSigner {
    operator_id: u32,
    public_key: PublicKey,
    secret_key: ZeroizingSecretKey,
}

impl SoftSigner {
    pub fn from_seed(operator_id: u32, seed: &[u8; SEED_BYTES]) -> SoftSigner {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftSigner {
            operator_id,
            public_key,
            secret_key: ZeroizingSecretKey::new(secret_key),
        }
    }
}

impl AttestationSigner for SoftSigner {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> Signature {
        let rnd = [0u8; 32];
        ml_dsa::sign(self.secret_key.expose(), message, context, &rnd)
            .expect("ml-dsa sign over an in-bounds context")
    }
}

pub trait SigningBackend {
    fn operator_id(&self) -> u32;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature;
}

pub struct EnclaveSigner<B: SigningBackend> {
    backend: B,
}

impl<B: SigningBackend> EnclaveSigner<B> {
    pub fn new(backend: B) -> EnclaveSigner<B> {
        EnclaveSigner { backend }
    }
}

impl<B: SigningBackend> AttestationSigner for EnclaveSigner<B> {
    fn operator_id(&self) -> u32 {
        self.backend.operator_id()
    }

    fn public_key(&self) -> PublicKey {
        self.backend.public_key()
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> Signature {
        self.backend.sign(message, context)
    }
}

pub struct SoftBackend {
    operator_id: u32,
    public_key: PublicKey,
    secret_key: ZeroizingSecretKey,
}

impl SoftBackend {
    pub fn from_seed(operator_id: u32, seed: &[u8; SEED_BYTES]) -> SoftBackend {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftBackend {
            operator_id,
            public_key,
            secret_key: ZeroizingSecretKey::new(secret_key),
        }
    }
}

impl SigningBackend for SoftBackend {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature {
        let rnd = [0u8; 32];
        ml_dsa::sign(self.secret_key.expose(), preimage, context, &rnd)
            .expect("ml-dsa sign over an in-bounds context")
    }
}

pub type SlotId = u64;
pub type SessionHandle = u64;
pub type ObjectHandle = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs11Error {
    SlotUnavailable,
    NotAuthenticated,
    LoginFailed,
    KeyNotProvisioned,
    SignRejected,
}

pub trait Pkcs11Module {
    fn open_session(&self, slot: SlotId) -> Result<SessionHandle, Pkcs11Error>;
    fn login(&self, session: SessionHandle, pin: &[u8]) -> Result<(), Pkcs11Error>;
    fn find_key(&self, session: SessionHandle, label: &[u8]) -> Result<ObjectHandle, Pkcs11Error>;
    fn export_public_key(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
    ) -> Result<PublicKey, Pkcs11Error>;
    fn sign(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
        preimage: &[u8],
        context: &[u8],
    ) -> Result<Signature, Pkcs11Error>;
}

pub struct Pkcs11Backend<M: Pkcs11Module> {
    module: M,
    operator_id: u32,
    session: SessionHandle,
    key_handle: ObjectHandle,
    public_key: PublicKey,
}

impl<M: Pkcs11Module> Pkcs11Backend<M> {
    pub fn connect(
        module: M,
        operator_id: u32,
        slot: SlotId,
        pin: &[u8],
        label: &[u8],
    ) -> Result<Pkcs11Backend<M>, Pkcs11Error> {
        let session = module.open_session(slot)?;
        module.login(session, pin)?;
        let key_handle = module.find_key(session, label)?;
        let public_key = module.export_public_key(session, key_handle)?;
        Ok(Pkcs11Backend {
            module,
            operator_id,
            session,
            key_handle,
            public_key,
        })
    }
}

impl<M: Pkcs11Module> SigningBackend for Pkcs11Backend<M> {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature {
        self.module
            .sign(self.session, self.key_handle, preimage, context)
            .expect("the operator key handle signs through the module")
    }
}

struct TokenSession {
    authenticated: bool,
}

pub struct SoftwareHsm {
    slot: SlotId,
    pin: Vec<u8>,
    label: Vec<u8>,
    key_handle: ObjectHandle,
    public_key: PublicKey,
    secret_key: ZeroizingSecretKey,
    sessions: RefCell<BTreeMap<SessionHandle, TokenSession>>,
    next_session: Cell<SessionHandle>,
}

impl Drop for SoftwareHsm {
    fn drop(&mut self) {
        secure_wipe(&mut self.pin);
    }
}

impl SoftwareHsm {
    pub fn provision_operator_key(
        slot: SlotId,
        pin: &[u8],
        label: &[u8],
        seed: &[u8; SEED_BYTES],
    ) -> SoftwareHsm {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftwareHsm {
            slot,
            pin: pin.to_vec(),
            label: label.to_vec(),
            key_handle: 0x51a1,
            public_key,
            secret_key: ZeroizingSecretKey::new(secret_key),
            sessions: RefCell::new(BTreeMap::new()),
            next_session: Cell::new(1),
        }
    }

    fn authenticated(&self, session: SessionHandle) -> Result<(), Pkcs11Error> {
        let sessions = self.sessions.borrow();
        match sessions.get(&session) {
            Some(state) if state.authenticated => Ok(()),
            _ => Err(Pkcs11Error::NotAuthenticated),
        }
    }
}

impl Pkcs11Module for SoftwareHsm {
    fn open_session(&self, slot: SlotId) -> Result<SessionHandle, Pkcs11Error> {
        if slot != self.slot {
            return Err(Pkcs11Error::SlotUnavailable);
        }
        let handle = self.next_session.get();
        self.next_session.set(handle + 1);
        self.sessions
            .borrow_mut()
            .insert(handle, TokenSession { authenticated: false });
        Ok(handle)
    }

    fn login(&self, session: SessionHandle, pin: &[u8]) -> Result<(), Pkcs11Error> {
        let mut sessions = self.sessions.borrow_mut();
        let state = sessions
            .get_mut(&session)
            .ok_or(Pkcs11Error::NotAuthenticated)?;
        if !ct_eq(pin, self.pin.as_slice()) {
            return Err(Pkcs11Error::LoginFailed);
        }
        state.authenticated = true;
        Ok(())
    }

    fn find_key(&self, session: SessionHandle, label: &[u8]) -> Result<ObjectHandle, Pkcs11Error> {
        self.authenticated(session)?;
        if label != self.label.as_slice() {
            return Err(Pkcs11Error::KeyNotProvisioned);
        }
        Ok(self.key_handle)
    }

    fn export_public_key(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
    ) -> Result<PublicKey, Pkcs11Error> {
        self.authenticated(session)?;
        if handle != self.key_handle {
            return Err(Pkcs11Error::KeyNotProvisioned);
        }
        Ok(self.public_key)
    }

    fn sign(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
        preimage: &[u8],
        context: &[u8],
    ) -> Result<Signature, Pkcs11Error> {
        self.authenticated(session)?;
        if handle != self.key_handle {
            return Err(Pkcs11Error::KeyNotProvisioned);
        }
        let rnd = [0u8; 32];
        ml_dsa::sign(self.secret_key.expose(), preimage, context, &rnd)
            .ok_or(Pkcs11Error::SignRejected)
    }
}

impl Pkcs11Module for Rc<SoftwareHsm> {
    fn open_session(&self, slot: SlotId) -> Result<SessionHandle, Pkcs11Error> {
        (**self).open_session(slot)
    }

    fn login(&self, session: SessionHandle, pin: &[u8]) -> Result<(), Pkcs11Error> {
        (**self).login(session, pin)
    }

    fn find_key(&self, session: SessionHandle, label: &[u8]) -> Result<ObjectHandle, Pkcs11Error> {
        (**self).find_key(session, label)
    }

    fn export_public_key(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
    ) -> Result<PublicKey, Pkcs11Error> {
        (**self).export_public_key(session, handle)
    }

    fn sign(
        &self,
        session: SessionHandle,
        handle: ObjectHandle,
        preimage: &[u8],
        context: &[u8],
    ) -> Result<Signature, Pkcs11Error> {
        (**self).sign(session, handle, preimage, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    const CTX: &[u8] = b"QUANTOVA/Q-ORACLE/ATTEST/v1";

    struct RemoteCustodian {
        inner: SoftBackend,
        calls: Cell<u32>,
    }

    impl SigningBackend for RemoteCustodian {
        fn operator_id(&self) -> u32 {
            self.inner.operator_id()
        }

        fn public_key(&self) -> PublicKey {
            self.inner.public_key()
        }

        fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature {
            self.calls.set(self.calls.get() + 1);
            self.inner.sign(preimage, context)
        }
    }

    #[test]
    fn enclave_signature_verifies_against_the_backend_key() {
        let backend = SoftBackend::from_seed(3, &[0x51u8; 32]);
        let pk = backend.public_key();
        let signer = EnclaveSigner::new(backend);

        let message = b"observed fact";
        let sig = signer.sign(message, CTX);
        assert_eq!(signer.operator_id(), 3);
        assert!(ml_dsa::verify(&pk, message, &sig, CTX));
    }

    #[test]
    fn every_signature_leaves_through_the_backend_seam() {
        let custodian = RemoteCustodian {
            inner: SoftBackend::from_seed(4, &[0x52u8; 32]),
            calls: Cell::new(0),
        };
        let pk = custodian.public_key();
        let signer = EnclaveSigner::new(custodian);

        let sig = signer.sign(b"observed fact", CTX);
        assert!(ml_dsa::verify(&pk, b"observed fact", &sig, CTX));
        assert_eq!(signer.backend.calls.get(), 1);
    }

    const SLOT: SlotId = 0x04;
    const PIN: &[u8] = b"operator-ceremony-pin";
    const LABEL: &[u8] = b"q-oracle/operator/attest";

    fn provisioned_token() -> Rc<SoftwareHsm> {
        Rc::new(SoftwareHsm::provision_operator_key(
            SLOT,
            PIN,
            LABEL,
            &[0x53u8; 32],
        ))
    }

    struct CountingModule {
        inner: Rc<SoftwareHsm>,
        sign_calls: Cell<u32>,
    }

    impl Pkcs11Module for CountingModule {
        fn open_session(&self, slot: SlotId) -> Result<SessionHandle, Pkcs11Error> {
            self.inner.open_session(slot)
        }

        fn login(&self, session: SessionHandle, pin: &[u8]) -> Result<(), Pkcs11Error> {
            self.inner.login(session, pin)
        }

        fn find_key(
            &self,
            session: SessionHandle,
            label: &[u8],
        ) -> Result<ObjectHandle, Pkcs11Error> {
            self.inner.find_key(session, label)
        }

        fn export_public_key(
            &self,
            session: SessionHandle,
            handle: ObjectHandle,
        ) -> Result<PublicKey, Pkcs11Error> {
            self.inner.export_public_key(session, handle)
        }

        fn sign(
            &self,
            session: SessionHandle,
            handle: ObjectHandle,
            preimage: &[u8],
            context: &[u8],
        ) -> Result<Signature, Pkcs11Error> {
            self.sign_calls.set(self.sign_calls.get() + 1);
            self.inner.sign(session, handle, preimage, context)
        }
    }

    #[test]
    fn pkcs11_backend_signature_verifies_against_the_token_key() {
        let token = provisioned_token();
        let backend = Pkcs11Backend::connect(token, 7, SLOT, PIN, LABEL)
            .expect("the provisioned operator key handle opens");
        let pk = backend.public_key();
        let signer = EnclaveSigner::new(backend);

        let message = b"observed lock on the source chain";
        let sig = signer.sign(message, CTX);
        assert_eq!(signer.operator_id(), 7);
        assert!(ml_dsa::verify(&pk, message, &sig, CTX));
    }

    #[test]
    fn pkcs11_backend_holds_only_a_handle_never_the_private_key() {
        use std::mem::size_of;

        assert!(size_of::<Rc<SoftwareHsm>>() <= size_of::<usize>() * 2);

        let footprint = size_of::<Pkcs11Backend<Rc<SoftwareHsm>>>();
        assert!(footprint >= ml_dsa::PUBLIC_KEY_BYTES);
        assert!(footprint < ml_dsa::SECRET_KEY_BYTES);
    }

    #[test]
    fn every_pkcs11_signature_leaves_through_the_module_seam() {
        let module = CountingModule {
            inner: provisioned_token(),
            sign_calls: Cell::new(0),
        };
        let backend = Pkcs11Backend::connect(module, 8, SLOT, PIN, LABEL)
            .expect("the provisioned operator key handle opens");
        let pk = backend.public_key();
        let signer = EnclaveSigner::new(backend);

        assert_eq!(signer.backend.module.sign_calls.get(), 0);
        let sig = signer.sign(b"observed lock on the source chain", CTX);
        assert!(ml_dsa::verify(&pk, b"observed lock on the source chain", &sig, CTX));
        assert_eq!(signer.backend.module.sign_calls.get(), 1);
    }

    #[test]
    fn an_unprovisioned_label_or_wrong_secret_cannot_reach_the_key() {
        let token = provisioned_token();

        let wrong_label = Pkcs11Backend::connect(Rc::clone(&token), 9, SLOT, PIN, b"unknown/label");
        assert_eq!(wrong_label.err(), Some(Pkcs11Error::KeyNotProvisioned));

        let wrong_pin = Pkcs11Backend::connect(Rc::clone(&token), 9, SLOT, b"guessed", LABEL);
        assert_eq!(wrong_pin.err(), Some(Pkcs11Error::LoginFailed));

        let wrong_slot = Pkcs11Backend::connect(token, 9, 0x99, PIN, LABEL);
        assert_eq!(wrong_slot.err(), Some(Pkcs11Error::SlotUnavailable));
    }

    #[test]
    fn the_operator_login_gates_the_key_handle() {
        let token = SoftwareHsm::provision_operator_key(SLOT, PIN, LABEL, &[0x54u8; 32]);
        let session = token.open_session(SLOT).expect("a session opens");

        assert_eq!(
            token.find_key(session, LABEL).err(),
            Some(Pkcs11Error::NotAuthenticated)
        );

        token
            .login(session, PIN)
            .expect("the operator pin authenticates the session");
        let handle = token
            .find_key(session, LABEL)
            .expect("the key handle resolves after login");
        let pk = token
            .export_public_key(session, handle)
            .expect("the token exports its public key");
        let sig = token
            .sign(session, handle, b"observed lock", CTX)
            .expect("the handle signs");
        assert!(ml_dsa::verify(&pk, b"observed lock", &sig, CTX));
    }

    #[test]
    fn the_operator_secret_key_wipes_to_zero() {
        let (_pk, sk) = ml_dsa::keygen(&[0x60u8; 32]);
        let mut key = ZeroizingSecretKey::new(sk);
        assert!(key.expose().iter().any(|&b| b != 0));
        key.clear_for_test();
        assert!(key.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn secure_wipe_clears_every_byte() {
        let mut buf = vec![0x5au8; 128];
        secure_wipe(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn the_pin_compare_scans_every_byte() {
        assert!(ct_eq(b"operator-ceremony-pin", b"operator-ceremony-pin"));
        assert!(!ct_eq(b"operator-ceremony-pin", b"operator-ceremony-piZ"));
        assert!(!ct_eq(b"operator-ceremony-pin", b"Zperator-ceremony-pin"));
        assert!(!ct_eq(b"operator-ceremony-pin", b"operator-ceremony-pins"));
    }
}
