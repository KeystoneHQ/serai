#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use group::ff::PrimeField;
use k256::Scalar;

use alloy_core::primitives::{Parity, Signature};
use alloy_consensus::{SignableTransaction, Signed, TxLegacy};

/// The Keccak256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  alloy_core::primitives::keccak256(data.as_ref()).into()
}

/// Deterministically sign a transaction.
///
/// This signs a transaction via setting `r = 1, s = 1`, and incrementing `r` until a signer is
/// recoverable from the signature for this transaction. The purpose of this is to be able to send
/// a transaction from a known account which no one knows the private key for.
///
/// This function panics if passed a transaction with a non-None chain ID. This is because the
/// signer for this transaction is only singular across any/all EVM instances if it isn't binding
/// to an instance.
pub fn deterministically_sign(tx: &TxLegacy) -> Signed<TxLegacy> {
  assert!(
    tx.chain_id.is_none(),
    "chain ID was Some when deterministically signing a TX (causing a non-singular signer)"
  );

  let mut r = Scalar::ONE;
  let s = Scalar::ONE;
  loop {
    // Create the signature
    let r_bytes: [u8; 32] = r.to_repr().into();
    let s_bytes: [u8; 32] = s.to_repr().into();
    let v = Parity::NonEip155(false);
    let signature = Signature::from_scalars_and_parity(r_bytes.into(), s_bytes.into(), v).unwrap();

    // Check if this is a valid signature
    let tx = tx.clone().into_signed(signature);
    if tx.recover_signer().is_ok() {
      return tx;
    }

    r += Scalar::ONE;
  }
}
