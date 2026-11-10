use bytes::Bytes;

use super::{Frame, FrameDecoder, FrameEncoder, FrameError};

mod decode_errors;
mod encode_errors;
mod stream;
mod wire;

fn encode(frame: &Frame) -> Bytes {
    FrameEncoder::encode_to_vec(frame).expect("encodes")
}

/// Feeds one complete frame and returns what came out.
fn decode_one(bytes: Bytes) -> Result<Option<Frame>, FrameError> {
    let mut decoder = FrameDecoder::new();
    decoder.push(&bytes)?;
    decoder.next_frame()
}
