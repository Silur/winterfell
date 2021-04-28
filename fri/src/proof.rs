// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriProofLayer {
    pub values: Vec<Vec<u8>>,
    pub paths: Vec<Vec<[u8; 32]>>,
    pub depth: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriProof {
    pub layers: Vec<FriProofLayer>,
    pub rem_values: Vec<u8>,
    pub partitioned: bool,
}

impl FriProofLayer {
    fn to_bytes(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let values_len = u32::try_from(self.values.len()).expect(
            "cannot serializes values_len as u32");
        let paths_len = u32::try_from(self.paths.len()).expect(
            "cannot serializes paths_len as u32");

        ret.extend_from_slice(&values_len.to_be_bytes());
        for value in &self.values {
            let value_len = u32::try_from(value.len()).expect(
                "cannot serializes value_len as u32");
            ret.extend_from_slice(&value_len.to_be_bytes());
            ret.extend(value);
        }
        for path in &self.paths {
            let path_len = u32::try_from(path.len()).expect(
                "cannot serializes path_len as u32");
            ret.extend_from_slice(&path_len.to_be_bytes());
            path.iter().for_each(|hash| ret.extend_from_slice(hash));
        }
        ret.push(self.depth);
        let ret_len = u32::try_from(ret.len()).unwrap().to_be_bytes();
        for i in 0..4 {
            ret.insert(i, ret_len[i])
        }
        ret
    }

    fn from_bytes(v: &[u8]) -> Self {
        let mut index: usize = 0;
        let values_len = u32::from_be_bytes(v[index..4].try_into().unwrap());
        index += 4;
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(values_len.try_into().unwrap());
        for _ in 0..values_len {
            let value_len = u32::from_be_bytes(v[index..4].try_into().unwrap())
                .try_into().unwrap();
            index += 4;
            values.push(v[index..value_len].try_into().unwrap());
            index += value_len;
        }

        let paths_len: usize = u32::from_be_bytes(v[index..4].try_into().unwrap())
            .try_into().unwrap();
        index += 4;
        let mut paths: Vec<Vec<[u8; 32]>> = Vec::with_capacity(paths_len.try_into().unwrap());
        for i in 0..paths_len {
            let path_len = u32::from_be_bytes(v[index..4].try_into().unwrap())
                .try_into().unwrap();
            index += 4;
            for _j in 0..path_len {
                paths[i].push(v[index..index+32].try_into().unwrap());
                index += 32;
            }
        }
        let depth:u8 = v[index];
        Self { values, paths, depth }
    }
}

impl FriProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let layers_len = u32::try_from(self.layers.len()).expect(
            "cannot serializes values_len as u32");
        let rem_values_len = u32::try_from(self.rem_values.len()).expect(
            "cannot serializes rem_values_len as u32");

        ret.extend_from_slice(&layers_len.to_be_bytes());
        for layer in &self.layers {
            ret.extend(layer.to_bytes());
        }
        ret.extend_from_slice(&rem_values_len.to_be_bytes());
        ret.push(self.partitioned as u8);
        let ret_len = u32::try_from(ret.len()).unwrap().to_be_bytes();
        for i in 0..4 {
            ret.insert(i, ret_len[i])
        }
        return ret;
    }

    fn from_bytes(v: &[u8]) -> Self {
        let mut index: usize = 0;
        let layers_len: usize = u32::from_be_bytes(v[index..4].try_into().unwrap())
            .try_into().unwrap();
        index += 4;
        let layers: Vec<FriProofLayer> = Vec::with_capacity(layers_len);
        for i in 0..layers_len {
            let layer_len: usize = u32::from_be_bytes(v[index..index+4].try_into().unwrap())
                .try_into().unwrap();
            index += 4;
            let layer: FriProofLayer = FriProofLayer::from_bytes(&v[index..index+layer_len]);
            index += layer_len;
        }
        let rem_values_len: usize = u32::from_be_bytes(v[index..4].try_into().unwrap())
            .try_into().unwrap();
        index += 4;
        let mut rem_values: Vec<u8> = Vec::with_capacity(rem_values_len);
        for i in 0..rem_values_len {
            rem_values[i] = v[index];
            index += 1;
        }
        let partitioned: bool = v[index] != 0;
        Self { layers, rem_values, partitioned }
    }
}
