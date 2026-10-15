# 不要对整个 crate 跑 `cargo fmt`

**日期**：2026-02 · **发现于**：接插件宿主接缝时

## 发生了什么

我为修 clippy 跑了 `cargo fmt -p synra-core -p synra-plugin-host`。结果是 94 个文件的 diff，
全部与我要写的功能无关。然后：

```
test no_crate_that_makes_a_promise_breaks_it ... FAILED
api-guard found violations beyond the three deviations this test records:
  link.rs:495: `fn is_a_timeout(...)` holds io::Error
  peer/wire.rs:147: `pub(crate) fn peer_went_away(...)` holds io::Error
```

## 为什么格式化会让守卫失败

`tools/api-guard/tests/stability.rs` 用**行号**标识三个已知偏差：

```rust
let expected = [
    "crates\\synra-core\\src\\link.rs:467",     // 私有 fn
    "crates\\synra-core\\src\\peer\\wire.rs:138", // pub(crate)
    "crates\\synra-core\\src\\peer\\wire.rs:160", // pub(super)
];
```

它按 `line.contains(known)` 匹配 api-guard 的输出。格式化把函数挪了行号，
`467` 不再匹配 `:495`，于是这条**早已存在**的偏差看起来像新违规。

所以：报出来的违规不是格式化引入的，是行号漂移让守卫认不出自己认识的东西。
把格式回退，守卫立刻恢复通过。

## 三条要记住的

1. **这个仓库不是 rustfmt-clean 的**（HEAD 上 `cargo fmt --all -- --check` 就已经报告 diff）。
   所以全量格式化从来不是这个仓库的工作流，全量跑它会一次性制造 94 个无关文件的 diff。
2. **守卫用行号记录偏差**，所以任何重排行号的改动都会打破它。要动这些行，
   得同时更新 `stability.rs` 里的列表 —— 而它自己也提醒了：偏差被修掉之后列表也要缩短。
3. **报错时先确认是不是自己造成的**。我差点把"`io::Error` 泄漏到 API"当成既有的架构问题去修，
   实际上 `git show HEAD:...` 三秒就能证明那两个函数在我动手之前就在那里。

## 该怎么做

- 只格式化**自己新写的文件**，不动既有的。
- 要对既有文件跑格式，先 `git diff --stat` 看清楚波及多少文件。
- 任何守卫失败，先 `git stash` 掉自己的改动跑一遍基线 —— 失败如果消失，那它就是自己造成的。
