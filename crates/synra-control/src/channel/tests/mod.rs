//! Control message round trips and framing fixtures.

use serde::{Deserialize, Serialize};

use super::{Decoder, encode};

fn round_trip<T>(message: &T) -> T
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let bytes = encode(message).expect("encodes");
    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    decoder
        .next_message()
        .expect("no error")
        .expect("a message")
}

mod messages;
mod framing;
mod version;
