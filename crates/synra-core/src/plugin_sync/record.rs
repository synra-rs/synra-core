use super::*;

/// 一条同步记录的标识。
///
/// 与会话标识分开：一轮会话可以产生不止一条记录（发起端与接收端各记自己的），
/// 而一条记录要能被单独引用、排序和去重。
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct SyncId(String);

impl SyncId {
    /// 一个标识，名字由调用方给。
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// 标识本身。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 这一轮是谁推给谁。
///
/// `#[non_exhaustive]` 是因为这个枚举会随同步方向增加（例如将来的「双方交换」），
/// 而 `synra-core` 是 semi-stable：加一个变体不该是下游的破坏性变更。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncDirection {
    /// 本机推给对端。
    Push,
    /// 对端推给本机。
    Pull,
}

/// 一轮同步的结局，三态。
///
/// ★ **而它不能叫 `SyncOutcome`。** 那个名字在本模块里已经是一个**不同**的东西：
/// 接收端做过哪些义务的清单（[`SyncOutcome`]）。文档 §5.5 的 `SyncOutcome` 是这三态，
/// 代码的 [`SyncOutcome`] 是记账 —— 同名不同物。给新的这个起一个准确的名字，
/// 比重命名一个已经有生产调用者的类型代价小。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncVerdict {
    /// 装上了。
    Succeeded,
    /// 双方已经一致，所以没有传输 —— 与失败不同，它不需要任何人做什么。
    Skipped {
        /// 为什么跳过。
        reason: String,
    },
    /// 被拒绝了。
    Failed {
        /// 原因。
        error: String,
    },
}

/// Why a [`SyncRecord`] could not be turned into a row, or read back out of one.
///
/// # Why this is not a [`SyncError`]
///
/// [`SyncError`] is why a receiver *refused* a round — a fact about the sync. This is why a record that was decided
/// correctly could not be written down — a fact about the database. A caller that collapsed the two would report a
/// storage failure as a protocol refusal, and the user would look for the wrong problem.
///
/// # Why it does not hold `serde_json::Error`
///
/// Because `synra-core` is semi-stable: a public signature naming another crate's error type promises that crate's
/// version, and a `serde_json` upgrade would then be this crate's breaking change. The text is kept instead, which is
/// what a caller does with it anyway.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the record does not survive its row: {why}")]
pub struct SyncRecordError {
    /// What the serialiser said.
    why: String,
}

impl SyncRecordError {
    /// The reason, as a sentence.
    #[must_use]
    pub fn why(&self) -> &str {
        &self.why
    }
}

/// 一次同步留下了什么，够 §5.5 的可观测性和界面用。
///
/// 这条记录**就是**那一步的产物：以前它只有四个字段（插件、对端、决定、时间），
/// 所以一次同步结束之后没有任何地方说得出来它成没成、传了多少。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// 这条记录自己的标识。
    pub id: SyncId,
    /// 哪个插件。
    pub plugin_id: PluginId,
    /// 对端当时持有什么版本，或本机推过去的版本。
    pub version: Option<String>,
    /// 谁推给谁。
    pub direction: SyncDirection,
    /// 哪台设备。
    pub peer: DeviceId,
    /// 当时的**决定**（推送 / 跳过 / 询问）。
    ///
    /// 与 `verdict` 不同，也不是它的前身：决定是第 ③ 步的产物，结局是第 ⑧ 步的产物，
    /// 而一次「决定推送、结果失败」的记录需要对这两件事都说得出来。
    pub action: SyncAction,
    /// 什么时候开始的，有符号毫秒。
    ///
    /// 有符号毫秒而不是 `SystemTime`：仓库里每一个时间戳都是这个形状
    /// （`Runtime` 的 `started_at_ms`、每一张表的时间列），而一个 `SyncRecord` 要与它们比较、
    /// 要能存进 SQLite。文档写的 `SystemTime` 是意图，这个形状是实现它的方式。
    pub started_at_ms: i64,
    /// 什么时候结束的，还没结束时为 `None`。
    pub finished_at_ms: Option<i64>,
    /// 结局，还没结束时为 `None`。
    ///
    /// 与 `finished_at_ms` 同时为空或有值：一条已经结束却没有结局的记录，
    /// 和一条有结局却没有结束时间的记录，都是自相矛盾的。
    pub verdict: Option<SyncVerdict>,
    /// 传了多少字节。
    pub bytes_transferred: u64,
    /// 这一轮属于哪条追踪，还没认出是哪一轮时为 `None`。
    pub trace_id: Option<TraceId>,
}

impl SyncRecord {
    /// A record of what a sync decided.
    #[must_use]
    pub const fn new(
        plugin_id: PluginId,
        peer: DeviceId,
        action: SyncAction,
        started_at_ms: i64,
    ) -> Self {
        // 一条刚刚开始的记录：没有结束时间、没有结局、没有字节。
        Self {
            id: SyncId(String::new()),
            plugin_id,
            version: None,
            direction: SyncDirection::Push,
            peer,
            action,
            started_at_ms,
            finished_at_ms: None,
            verdict: None,
            bytes_transferred: 0,
            trace_id: None,
        }
    }

    /// 把这一轮写成库里的一行（迁移 v10 的 `sync_log`）。
    ///
    /// ★ 形状照 `intents`（迁移 v9）的先例：**整份文档 + 查询用的投影列**。
    /// `document` 是整份记录的序列化；旁边的列是历史页面真正要问的两个问题
    /// （最新在前、按插件过滤）。它们必须与 `document` 里的同一件事一致，
    /// 而这里保证这一点的方式是：两者都从**同一个** `self` 取。
    ///
    /// # Errors
    ///
    /// [`SyncRecordError`] when the record does not serialise. For a type made of plain data that cannot happen, but
    /// the workspace forbids `unwrap`, so "cannot happen" still has to be carried by somebody.
    pub fn to_row(&self) -> Result<synra_store::records::SyncLogRow, SyncRecordError> {
        Ok(synra_store::records::SyncLogRow {
            sync_id: self.id.as_str().to_owned(),
            plugin_id: self.plugin_id.to_string(),
            peer_device: self.peer.to_string(),
            started_at_ms: self.started_at_ms,
            finished_at_ms: self.finished_at_ms,
            // ★ The external error type is not named on a line that declares anything: a `From` impl, or even a private
            // `fn`, would put `serde_json::Error` in this semi-stable crate's public surface, and the closure keeps it
            // to the value being converted.
            document: serde_json::to_string(self).map_err(|error| SyncRecordError {
                why: error.to_string(),
            })?,
        })
    }

    /// 从库里的一行读回这一轮。
    ///
    /// ★ **`document` 是权威。** 投影列是给查询用的索引；与文档不一致的列只可能来自有人手工改过库，
    /// 而那时相信哪一半都不对 —— 这里选择相信完整的那一半，并把不一致留给一个单独的检查
    /// （而不是在这里悄悄让列赢）。
    ///
    /// # Errors
    ///
    /// [`SyncRecordError`] when the document is not this record's serialisation — a row written by another build, or
    /// edited by hand, which is the case the projection columns exist to be checked against.
    pub fn from_row(row: &synra_store::records::SyncLogRow) -> Result<Self, SyncRecordError> {
        serde_json::from_str(&row.document).map_err(|error| SyncRecordError {
            why: error.to_string(),
        })
    }

    /// 给记录一个身份、一个方向、一个版本和一条追踪。
    ///
    /// 分开而不是塞进 `new`：`new` 的调用点只关心「决定了什么」，
    /// 而身份与追踪是这一轮被真正记下来时才有的东西。
    #[must_use]
    pub fn identified(
        mut self,
        id: SyncId,
        direction: SyncDirection,
        version: Option<String>,
        trace_id: TraceId,
    ) -> Self {
        self.id = id;
        self.direction = direction;
        self.version = version;
        self.trace_id = Some(trace_id);
        self
    }

    /// 收尾：结局、字节数与结束时间。
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] 当这条记录已经收过尾 —— 收两次的结局覆盖第一次，
    /// 而那正是「最后的说法赢」这种没人看得出来的错。
    pub fn finished(
        mut self,
        verdict: SyncVerdict,
        bytes_transferred: u64,
        at_ms: i64,
    ) -> Result<Self, SyncError> {
        if self.verdict.is_some() {
            return Err(SyncError::StepRefused {
                step: "sync-record",
                why: "this record already has a verdict, and a second one would silently replace the first".to_owned(),
            });
        }
        self.verdict = Some(verdict);
        self.bytes_transferred = bytes_transferred;
        self.finished_at_ms = Some(at_ms);
        Ok(self)
    }

    /// A sentence for a log line.
    #[must_use]
    pub fn describe(&self) -> String {
        let why = match &self.action {
            SyncAction::Push { why } | SyncAction::Skip { why } | SyncAction::Refuse { why } => {
                why.as_str()
            }
            SyncAction::Ask { ours, theirs } => {
                return format!(
                    "{} on {}: ask, this device has {ours} and the other has {}",
                    self.plugin_id,
                    self.peer,
                    theirs.as_deref().unwrap_or("nothing")
                );
            }
        };
        format!(
            "{} on {}: {} ({why})",
            self.plugin_id,
            self.peer,
            self.action.as_str()
        )
    }
}

/// Every device's last known state for one plugin, so a report can say what is where.
#[derive(Debug, Clone, Default)]
pub struct SyncTable {
    entries: BTreeMap<(PluginId, DeviceId), RemoteState>,
}

impl SyncTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ⑨ 的第一半：发起端把一轮同步的结局写进它对本机的认识。
    ///
    /// ★ **为什么这条是 `record` 唯一的<ins>生产</ins>调用者。**
    ///
    /// 这张表能存、能查、能按插件列出，但从写下来那天起没有任何东西把一次同步的**结果**写进去，
    /// 所以 §5.2 第 ⑨ 步（「A 更新同步状态，UI 显示」）没有实现 —— 表和回复都在，缺的是把两半接起来的这一行。
    ///
    /// ★ **而失败时不改这张表，这是语义而不是省事。**
    ///
    /// 一次失败的同步没有改变对端持有什么：它仍然有原来那个版本。写成「什么也没有」会让下一次推送判断成
    /// 「它需要」，于是重复传输；写成「新版本」更糟 —— 表会声称对端有一个它从未收到的包。
    /// 失败属于**历史**（§5.5 的 `SyncRecord`），不属于「对端现在有什么」。
    ///
    /// ★ 而摘要从**参数**来，不从回复来：回复里没有摘要，也不需要 —— 发起端推的就是那个包，摘要是它自己算的。
    /// 让对端回报摘要会多一个可以撒谎的地方。
    pub fn apply_result(
        &mut self,
        device: DeviceId,
        plugin_id: &PluginId,
        result: &crate::messaging::SyncResult,
        pushed_digest: &str,
    ) {
        if !result.ok {
            return;
        }
        // 说成功却没有版本，是回复自相矛盾。不更新好过记一个半真半假的状态。
        let Some(version) = result.installed_version.clone() else {
            return;
        };
        self.record(
            device,
            RemoteState {
                plugin_id: plugin_id.clone(),
                version: Some(version),
                digest: Some(pushed_digest.to_owned()),
                active: result.activated,
            },
        );
    }

    /// Loads this table from rows read out of a database.
    ///
    /// ★ **Why this exists.**
    ///
    /// `SyncTable` is the in-memory answer to "what does each device hold"; `sync_records` is the durable one. They are
    /// not duplicates — a kernel without SQLite can use this one — but nothing could get from one to the other, so a
    /// host that read the rows had nowhere to put what it read.
    ///
    /// ★ **One-way on purpose.** The database is the record, and a table that could write back would be a second author
    /// of it — the arrangement this codebase keeps replacing with "one place decides, the rest read".
    ///
    /// ★ **An empty version or digest becomes `None` rather than `Some("")`.** The receiving side writes a row with the
    /// digest the *file* proved and leaves the version empty, because a `Decision` does not carry one. `Some("")` would
    /// read as the claim "the peer holds version ''" rather than as the silence it is — and `has_it` is exactly the
    /// question that would then be answered wrongly.
    ///
    /// ★ **A row this build cannot parse is skipped rather than refused.** The identifier came from a device that may
    /// run another build, and a table that refused to load at all would take the rest of the history down with it.
    #[must_use]
    pub fn from_rows(rows: &[synra_store::records::SyncRow]) -> Self {
        let mut table = Self::new();
        for row in rows {
            let (Ok(plugin_id), Ok(device)) = (
                PluginId::try_from(row.plugin_id.clone()),
                row.peer_device.parse::<DeviceId>(),
            ) else {
                continue;
            };
            table.record(
                device,
                RemoteState {
                    plugin_id,
                    version: Some(row.version.clone()).filter(|version| !version.is_empty()),
                    digest: Some(row.digest.clone()).filter(|digest| !digest.is_empty()),
                    // A row says the peer holds these bytes. Whether it is *running* them is not something this table
                    // was ever told, and guessing would be the kind of claim this codebase keeps removing.
                    active: false,
                },
            );
        }
        table
    }

    /// Records what a device has.
    pub fn record(&mut self, device: DeviceId, state: RemoteState) {
        let _ = self
            .entries
            .insert((state.plugin_id.clone(), device), state);
    }

    /// What a device has, if anything is known.
    #[must_use]
    pub fn state_of(&self, plugin_id: &PluginId, device: DeviceId) -> Option<&RemoteState> {
        self.entries.get(&(plugin_id.clone(), device))
    }

    /// Every device's state for one plugin, ordered by device so two reports agree.
    #[must_use]
    pub fn for_plugin(&self, plugin_id: &PluginId) -> Vec<(DeviceId, &RemoteState)> {
        self.entries
            .iter()
            .filter(|((plugin, _), _)| plugin == plugin_id)
            .map(|((_, device), state)| (*device, state))
            .collect()
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
