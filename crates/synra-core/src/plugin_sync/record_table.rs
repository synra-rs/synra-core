use super::*;

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
