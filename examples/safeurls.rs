// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use sn_url::{DataType, Error, SafeUrl, XorUrlBase};
use xor_name::XorName;

fn main() -> Result<(), Error> {
    // Let's generate a random XorName
    let xorname = XorName::random(&mut rand::thread_rng());

    // We can encode a SafeKey XOR-URL using the Xorname
    // and specifying Base32z as the base encoding for it
    let xorurl = SafeUrl::from_safekey(xorname)?.encode(XorUrlBase::Base32z);

    println!("XorUrl: {}", xorurl);

    // We can parse a Safe-URL string and obtain a SafeUrl instance
    let safe_url = SafeUrl::from_url(&xorurl)?;

    assert_eq!(safe_url.data_type(), DataType::SafeKey);
    println!("Data type: {}", safe_url.data_type());

    assert_eq!(safe_url.xorname(), xorname);
    println!("Xorname: {}", safe_url.xorname());

    Ok(())
}
