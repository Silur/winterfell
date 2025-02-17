// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub mod hash;
pub use hash::Hasher;

pub mod merkle;
pub use merkle::{build_merkle_nodes, BatchMerkleProof, MerkleTree};

pub mod merkle2;

mod random;
pub use random::{DefaultRandomElementGenerator, RandomElementGenerator};

pub type HashFunction = fn(&[u8], &mut [u8]);
