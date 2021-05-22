// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::errors::{Error, Result};
use xor_name::XorName;

// Number of bytes to use for the checksum
const CHECKSUM_BYTES_LENGTH: usize = 4;

// Calculate four bytes sha3-256 checksum
pub fn calculate_checksum_bytes(bytes: &[u8]) -> Vec<u8> {
    // we use XorName as helper since it computes a sha3-256
    let hash = XorName::from_content(&[bytes]);
    hash[0..CHECKSUM_BYTES_LENGTH].to_vec()
}

// Verifies checksum matches returning the bytes without the checksum
pub fn verify_checksum(bytes: &[u8]) -> Result<&[u8]> {
    let len = bytes.len();
    if len <= CHECKSUM_BYTES_LENGTH {
        return Err(Error::Checksum);
    }

    let data = &bytes[..len - CHECKSUM_BYTES_LENGTH];
    let checksum = calculate_checksum_bytes(&data);

    if bytes[len - CHECKSUM_BYTES_LENGTH..] == checksum {
        Ok(data)
    } else {
        Err(Error::Checksum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};

    #[test]
    fn test_checksum_valid() -> Result<()> {
        let input = b"012345678901234567890";
        let checksum = calculate_checksum_bytes(input);
        assert_eq!(checksum, vec![0x71, 0x78, 0x57, 0x89]);

        let mut checksumed_input = input.to_vec();
        checksumed_input.extend(checksum);
        assert_eq!(verify_checksum(&checksumed_input)?, input);

        Ok(())
    }

    #[test]
    fn test_checksum_short_input() -> Result<()> {
        let input = b"0123";

        if let Err(Error::Checksum) = verify_checksum(input) {
            Ok(())
        } else {
            Err(anyhow!("Checksum verification was expected to fail"))
        }
    }

    #[test]
    fn test_checksum_fail() -> Result<()> {
        let mut input = b"012345678901234567890".to_vec();
        let checksum = calculate_checksum_bytes(&input);
        input.extend(checksum);

        // corrupt input
        input.insert(5, 5);

        if let Err(Error::Checksum) = verify_checksum(&input) {
            Ok(())
        } else {
            Err(anyhow!("Checksum verification was expected to fail"))
        }
    }
}
