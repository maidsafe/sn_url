// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use multibase::Base;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::{
    fmt::{self, Display},
    str::FromStr,
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum VersionHashError {
    #[error("Decoding error")]
    DecodingError(#[from] multibase::Error),
    #[error("Invalid hash length")]
    InvalidHashLength,
    #[error("Invalid encoding (must be Base32Z)")]
    InvalidEncoding,
}

/// Version of content (represented with a hash) when such content is mutable data
#[derive(Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Clone, Copy)]
pub struct VersionHash([u8; 32]);

impl VersionHash {
    pub fn new(hash_bytes: [u8; 32]) -> Self {
        Self(hash_bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for VersionHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base32z = multibase::encode(Base::Base32Z, self.0);
        write!(f, "{}", base32z)
    }
}

impl FromStr for VersionHash {
    type Err = VersionHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (base, data) = multibase::decode(s)?;
        if base != Base::Base32Z {
            return Err(VersionHashError::InvalidEncoding);
        }

        let hash_bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| VersionHashError::InvalidHashLength)?;

        Ok(VersionHash(hash_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use color_eyre::{eyre::bail, Result};

    #[test]
    fn test_version_hash_encode_decode() -> Result<()> {
        let string_hash_32bits = "hqt1zg7dwci3ze7dfqp48e3muqt4gkh5wqt1zg7dwci3ze7dfqp4y";
        let vh = VersionHash::from_str(string_hash_32bits)?;
        let str_vh = vh.to_string();
        assert_eq!(&str_vh, string_hash_32bits);
        Ok(())
    }

    #[test]
    fn test_version_hash_decoding_error() -> Result<()> {
        let string_hash = "hxf1zgedpcfzg1ebbhxf1zgedpcfzg1ebbhxf1zgedpcfzg1ebb";
        match VersionHash::from_str(string_hash) {
            Err(VersionHashError::DecodingError(_)) => Ok(()),
            _ => bail!("Should have triggered a DecodingError"),
        }
    }

    #[test]
    fn test_version_hash_invalid_encoding() -> Result<()> {
        let string_hash = "900573277761329450583662625";
        let vh = VersionHash::from_str(string_hash);
        assert_eq!(vh, Err(VersionHashError::InvalidEncoding));
        Ok(())
    }

    #[test]
    fn test_version_hash_invalid_len() -> Result<()> {
        let string_hash = "hxf1zgedpcfzg1ebb";
        let vh = VersionHash::from_str(string_hash);
        assert_eq!(vh, Err(VersionHashError::InvalidHashLength));
        Ok(())
    }
}
