// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use thiserror::Error;

/// Custom Result type for url crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type returned by the API
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// InvalidXorUrl
    #[error("InvalidXorUrl: {0}")]
    InvalidXorUrl(String),
    /// InvalidInput
    #[error("InvalidInput: {0}")]
    InvalidInput(String),
    /// UnsupportedMediaType
    #[error("UnsupportedMediaType: {0}")]
    UnsupportedMediaType(String),
}
