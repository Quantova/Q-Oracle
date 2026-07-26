#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The oracle data plane.
//!
//! [`q_qbridge::handle`] is the whole runtime as a pure function of `(BridgeState, Request)`. This
//! crate is the transport that wraps it. A bounded, hand-rolled HTTP server over `std::net` decodes
//! a request frame into a [`q_qbridge::Request`], calls `handle` over a shared [`q_qbridge::BridgeState`]
//! behind a mutex, encodes the returned [`q_qbridge::Response`], and writes it. There is no async
//! runtime and no heavy networking dependency.
//!
//! A deposit is admitted, not minted, here. The authoritative on-chain mint for a proof-backed
//! corridor stays at the seam `q_federated::trustless` documents. This crate never opens a
//! no-quorum mint entry point.

pub mod json;
pub mod wire;

pub use json::Json;
pub use wire::{decode_request, decode_response, encode_request, encode_response, method_of, WireError};
