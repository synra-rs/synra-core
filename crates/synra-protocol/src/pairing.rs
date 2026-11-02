//! 配对：一段由人比对的六位码，和两端的答复。
//!
//! # 这一层只负责「说的是什么」
//!
//! 码什么时候生成、什么时候作废、谁该写 `paired_devices`，都属于内核的配对会话（`synra_core::pairing`）。
//! 这里只有载荷的形状和它的校验——理由和传输消息一样：一条消息是否合法不该依赖一条正在跑的链路，
//! 否则它只能在集成测试里被验。
//!
//! # 码为什么是六位十进制
//!
//! 因为它要被**两个人用眼睛比对**：六位短到一次能记住，长到同网段偶然撞上可以忽略（百万分之一量级）。
//! 码不参与任何密码学运算：它防的是「同一网段里另一台同名设备」，不是窃听。这也是 ADR-025
//! 把加密整体推迟之后唯一保留下来的「确认」。

use serde::{Deserialize, Serialize};

use crate::ids::DeviceId;
use crate::session::PlatformKind;

/// 发起方请求配对。载荷是 [`PairRequest`]。
pub const PAIR_REQUEST: &str = "_synra.pair.request";
/// 接收方答复。载荷是 [`PairResponse`]。
pub const PAIR_RESPONSE: &str = "_synra.pair.response";
/// 发起方在对方答复前撤回。无载荷。
pub const PAIR_CANCEL: &str = "_synra.pair.cancel";

/// 六位配对码的上限，表示「正好六位」而不是「六位以内」。
pub const PAIR_CODE_LIMIT: u32 = 1_000_000;

/// 一个码为什么不是码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairCodeError {
    /// 不是六位十进制数字。
    NotSixDigits,
    /// 六位，但数值越界。
    OutOfRange,
}

impl core::fmt::Display for PairCodeError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotSixDigits => out.write_str("a pairing code is six decimal digits"),
            Self::OutOfRange => out.write_str("a pairing code is below one million"),
        }
    }
}

impl core::error::Error for PairCodeError {}

/// 六位配对码。
///
/// 保存的是**数值**而不是字符串：前导零是格式，不是内容，`000123` 与 `123` 必须是同一个码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PairCode(u32);

impl PairCode {
    /// 包起来一个已经合法的值。
    ///
    /// # Errors
    ///
    /// 越界时拒绝，调用方拿到的码因此永远打印成六位。
    pub fn new(value: u32) -> Result<Self, PairCodeError> {
        if value < PAIR_CODE_LIMIT {
            Ok(Self(value))
        } else {
            Err(PairCodeError::OutOfRange)
        }
    }

    /// 一个新的码，来自操作系统的熵源。
    ///
    /// 取模带来的偏差约万分之四；对一个「让人看一眼」的数字没有意义，而拒绝采样只会让这段代码更难读。
    #[must_use]
    pub fn generate() -> Self {
        Self((DeviceId::new().as_uuid().as_u128() as u32) % PAIR_CODE_LIMIT)
    }

    /// 从用户或对端给的字符串读回一个码。
    ///
    /// # Errors
    ///
    /// 不是恰好六位十进制数字时拒绝：短一位可能来自截断，长一位可能来自拼接，两种都不该被当成同一个码。
    pub fn parse(text: &str) -> Result<Self, PairCodeError> {
        if text.len() != 6 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PairCodeError::NotSixDigits);
        }
        let value: u32 = text.parse().map_err(|_| PairCodeError::NotSixDigits)?;
        Self::new(value)
    }

    /// 数值本身。
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// 六位，带前导零。
    #[must_use]
    pub fn as_text(self) -> String {
        format!("{:06}", self.0)
    }
}

impl core::fmt::Display for PairCode {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "{:06}", self.0)
    }
}

/// 发起方的请求：码，加上「我是谁」。
///
/// 名称与平台一起出现，是因为接收方要能把「哪个请求」和「屏幕上那台设备」对上：
/// 只给一串 `device_id` 的弹窗，等于让人凭十六进制字符做决定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequest {
    /// 六位码，作为字符串传输，保留前导零。
    pub code: String,
    /// 发起方自称的设备标识。
    pub from: DeviceId,
    /// 发起方展示给对端的名称。
    pub display_name: String,
    /// 发起方的平台。
    pub platform: PlatformKind,
}

impl PairRequest {
    /// 用码和一份身份组装请求。
    #[must_use]
    pub fn new(
        code: PairCode,
        from: DeviceId,
        display_name: impl Into<String>,
        platform: PlatformKind,
    ) -> Self {
        Self {
            code: code.as_text(),
            from,
            display_name: display_name.into(),
            platform,
        }
    }

    /// 把码读回来。
    ///
    /// # Errors
    ///
    /// 载荷里的码不是六位十进制时拒绝——对端给的字符串不能直接拿去比对。
    pub fn code(&self) -> Result<PairCode, PairCodeError> {
        PairCode::parse(&self.code)
    }
}

/// 接收方的答复。
///
/// 只有「接受」与否，没有自由文本理由：拒绝是需要理由的决定，不是需要理由的消息。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResponse {
    /// 对方是否接受。
    pub accepted: bool,
}

impl PairResponse {
    /// 接受。
    #[must_use]
    pub const fn accept() -> Self {
        Self { accepted: true }
    }

    /// 拒绝。
    #[must_use]
    pub const fn refuse() -> Self {
        Self { accepted: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_device() -> DeviceId {
        DeviceId::new()
    }

    #[test]
    fn a_code_keeps_its_leading_zeroes() {
        let code = PairCode::new(123).expect("in range");
        assert_eq!(code.as_text(), "000123");
        assert_eq!(code.to_string(), "000123");
    }

    #[test]
    fn a_code_round_trips_through_the_text_a_person_reads() {
        let code = PairCode::generate();
        assert_eq!(PairCode::parse(&code.as_text()), Ok(code));
    }

    #[test]
    fn five_or_seven_digits_are_refused() {
        assert_eq!(PairCode::parse("12345"), Err(PairCodeError::NotSixDigits));
        assert_eq!(PairCode::parse("1234567"), Err(PairCodeError::NotSixDigits));
        assert_eq!(PairCode::parse("12a456"), Err(PairCodeError::NotSixDigits));
        assert_eq!(PairCode::parse(""), Err(PairCodeError::NotSixDigits));
    }

    #[test]
    fn a_million_is_not_a_code() {
        assert_eq!(PairCode::new(1_000_000), Err(PairCodeError::OutOfRange));
        assert!(PairCode::new(999_999).is_ok());
    }

    #[test]
    fn a_request_carries_the_code_as_six_digits() {
        let request = PairRequest::new(
            PairCode::new(42).expect("in range"),
            a_device(),
            "Pixel",
            PlatformKind::Android,
        );
        assert_eq!(request.code, "000042");
        assert_eq!(request.code().expect("six digits"), PairCode::new(42).expect("in range"));
    }

    #[test]
    fn a_request_with_a_malformed_code_cannot_be_read_back() {
        let request = PairRequest {
            code: "42".to_owned(),
            from: a_device(),
            display_name: "Pixel".to_owned(),
            platform: PlatformKind::Android,
        };
        assert_eq!(request.code(), Err(PairCodeError::NotSixDigits));
    }

    #[test]
    fn a_response_says_only_whether_it_was_accepted() {
        assert!(PairResponse::accept().accepted);
        assert!(!PairResponse::refuse().accepted);
    }
}