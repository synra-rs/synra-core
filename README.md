# synra-core

> **内核仓库。** Rust workspace：线协议、发现与传输、领域内核、插件沙箱。
>
> 这是 **`synra` 三仓库拓扑**中的第 1 个（[设计文档 §3](https://github.com/synra-rs/design-docs)）：
>
> | 仓库                                                    | 装什么                                     |
> | ------------------------------------------------------- | ------------------------------------------ |
> | **`synra-core`** ← 本仓库                                 | Rust 内核 + CLI + 插件工具链                   |
> | [`synra-app`](https://github.com/synra-rs/synra-app)      | Tauri 应用（桌面 + 移动 + 宿主 UI）             |
> | [`design-docs`](https://github.com/synra-rs/design-docs)  | 设计文档（唯一权威）                           |
>
> ✅ **已在实现中。** 25 个 workspace 成员：16 个库、2 个二进制（`synra-cli` / `synra-daemon`）、7 个工具
> （插件 CLI、WIT 代码生成、结构守卫、API 快照守卫、feature 矩阵、文档链接、文档数量断言）。线协议、能力 DSL、UDP 发现与 TCP 传输、配对、会话与传输、
> SQLite 存储、可观测性、插件沙箱（能力表、配额、生命周期、实例池、执行层）都已落地并有单测。
>
> 未完成的部分写在每个 crate 的 `lib.rs` 顶部（"what is not here"）与 [19 路线图](https://github.com/synra-rs/design-docs/blob/main/19-roadmap.md)；

---

## 开发工具链

开发版本与 rustfmt、Clippy 由 [rust-toolchain.toml](./rust-toolchain.toml) 固定。
在仓库内执行 `rustup toolchain install --no-self-update` 安装后，照常运行 Cargo 命令；
最低支持版本仍由 Cargo.toml 声明，验证时显式使用 `cargo +<msrv>`，不会改变默认开发版本。
交叉编译目标按需要另行安装，工具链升级与对应检查结果一起审阅。

## 这个仓库将装什么

```
synra-core/
├─ Cargo.toml                     # [workspace] resolver="3", edition 2024, MSRV 1.88
├─ STABILITY.md                   # ★ 稳定性分级（哪些 crate 遵守 SemVer，见设计文档 26 §2）
├─ rustfmt.toml / deny.toml / clippy 配置
├─ .cargo/config.toml             # 移动端目标与链接参数
├─ justfile + xtask/              # 任务入口 + 结构守卫
├─ crates/                        # 内核 crate
│  ├─ synra-protocol/             #   线协议（★ 无 IO 依赖：不依赖 tokio/rusqlite/wasmtime）
│  ├─ synra-capability/           #   capability DSL（纯函数，无分配匹配）
│  ├─ synra-net/                  #   发现（UDP/mDNS）+ 传输（TCP）
│  ├─ synra-store/                #   SQLite + 文件沙箱 + 密钥
│  ├─ synra-observe/              #   tracing / metrics / 诊断包
│  ├─ synra-plugin-api/           #   插件契约（纯类型 + WIT 绑定）
│  ├─ synra-plugin-host/          #   ★ Wasm 沙箱 + 能力闸门 + 生命周期
│  ├─ synra-plugin-ui/            #   UI 插件 artifact 管理（不含渲染）
│  ├─ synra-platform/             #   trait Platform + 各平台实现
│  ├─ synra-core/                 #   ★ 领域内核 + 编排
│  └─ synra-testkit/              #   测试夹具（publish = false）
├─ apps/
│  ├─ synra-cli/                  #   薄宿主，也是"内核不依赖 UI"的架构验收工具
│  └─ synra-daemon/               #   无 UI 守护进程（是否要做待定）
├─ tools/
│  ├─ synra-plugin-cli/           #   插件作者工具链（new/build/verify/sign/publish/dev）
│  └─ wit-codegen/                #   WIT → Rust/TS 绑定生成
├─ wit/synra-plugin.wit           # ★ 插件接口定义（单一真相源）
├─ api/*.txt                      # ★ cargo public-api 快照（"核心要稳"的守卫）
├─ fixtures/wire/                 #   线协议逐字节 fixture
├─ benches/ + fuzz/               #   性能门禁 + 模糊测试
└─ spike/                         # ★ M0 的技术验证（8 个，动手前必须跑）
```

## 它不装什么

| 不装                        | 在哪                                                    |
| --------------------------- | ------------------------------------------------------- |
| Tauri 应用（桌面 / 移动）     | [`synra-app`](https://github.com/synra-rs/synra-app)      |
| 前端（Vue / Vite）           | 同上                                                     |
| 插件 UI 的类型库              | [`synra-client`](https://github.com/synra-rs/synra-client) |
| 设计文档                     | [`design-docs`](https://github.com/synra-rs/design-docs)  |

**铁律**：本仓库的**任何** crate 都不得依赖 `tauri` / `wry` / `tao` / 任何 GUI 库。
`apps/synra-cli` 能在没有 WebView 的环境里完成发现、配对、收发、插件执行 —— 这是这条铁律的验收标准。

## CLI 插件更新

先启动同一数据目录下的 daemon；CLI 与 daemon 使用相同的 `SYNRA_DATA_DIR`。

```text
synra plugin registry https://registry.example static:https://cdn.example/plugins
synra plugin policy auto-minor
synra plugin publisher list
synra plugin publisher decide @acme trusted --fingerprint "AB12 CD34 EF56 7890"
synra plugin publisher decide @acme revoked --fingerprint "AB12 CD34 EF56 7890"
synra plugin check
synra plugin check @acme/hello
synra plugin update @acme/hello --version ^1.1
```

`registry`、`policy` 无参数时读取当前设置，`registry --clear` 清除更新源。手动检查不受后台策略或每日缓存限制，
也不会自动安装；失败报告保留上次答案并让 CLI 以非零状态退出。手动更新必须前进，新增权限需要再次
`plugin consent` 和 `plugin enable`；未经批准的公钥变化、撤销版本和安全模式均不能靠手动更新绕过。

## 对外接触点（只有三个）

| # | 接触点                        | 形态                                                         |
| - | ----------------------------- | ------------------------------------------------------------ |
| 1 | **Rust API**                   | `synra-core` 的 `Kernel::{bootstrap, start, shutdown, subscribe, snapshot}` |
| 2 | **TypeScript 类型**             | `ts-rs` 生成 → `synra-client` 的 `@synra/protocol` 包            |
| 3 | **插件契约（WIT）**              | `wit/synra-plugin.wit` → 插件 SDK 与宿主实现                    |

除此外，`synra-app` **不得**依赖 `synra-net` / `synra-store` / `synra-plugin-host` 的内部类型。

## 下一步

1. **读设计文档** → [`design-docs`](https://github.com/synra-rs/design-docs)
   - 先读 [26 核心稳定性、封装与性能](https://github.com/synra-rs/design-docs/blob/main/26-core-stability-and-perf.md)
     与 [11 设计原则](https://github.com/synra-rs/design-docs/blob/main/11-design-principles.md)（已踩过的坑）；
   - 再读 [06 Workspace 与 Crate 规划](https://github.com/synra-rs/design-docs/blob/main/06-workspace-layout.md)。
2. **M0 的技术验证 spike**（[19 路线图 §0.1](https://github.com/synra-rs/design-docs/blob/main/19-roadmap.md)）
   —— Android 交叉编译（wasmtime + rusqlite）已通过；`wasmtime` 组件模型在
   `cargo test -p synra-plugin-host --features wasm-runtime` 下有真实组件的单测。**仍缺 spike 5 与 6**
   （多 WebView 独立 origin、CSP 拦 fetch）—— 这两条在桌面上就能跑，是插件 UI 承载的前置。
3. **接下来要做的**（按依赖顺序）：
   - ~~把安装链路接上 11 步校验~~ —— **2026-10-18 接上了本地目录这一半**：`Request::PluginInstall` →
     `Kernel::plugin_install` → `runtime/install.rs`（11 步校验 → 原子落盘 → 写一行 `enabled=false, trusted=false`），
     所以 `verify::verify` 不再没有生产调用者。仍然缺：registry 安装（全仓无 HTTP 客户端）、逐项授权的
     `plugin_grants` 写入方、以及 app 侧的 `plugins_install`；
   - **一个示例插件 + 恶意插件套件的最小集**：让"越权被闸门拦住、内核与其它插件仍然可用"有测试，
     而不是只有脚本后端上的断言；
   - `synra-core` 的 `plugins` feature —— `cargo run -p matrix` 里那一行 SKIP 的唯一原因；
   - 前端接上：`synra-app` 注册了 22/40 条命令，事件桥还不存在。安装命令（`plugins_install`）已接上，
     它调用的是同一个 `synra_core::install`；插件页还差 UI。

   CI 已经就位（`.github/workflows/ci.yml`：clippy / test / MSRV / guards / matrix），所以上面每一条
   落地之后都不需要再"记得跑一遍"。

## NOTES

[`NOTES/`](./NOTES) holds two kinds of record: bugs that cost more to *find* than to fix, written so the next
investigation starts from them, and decisions whose reasoning would otherwise live only in a conversation. Neither
is user documentation and neither is a changelog.

- [A 6-second transfer, and four rounds spent looking in the wrong place](./NOTES/2026-02-transfer-six-seconds.md)
  — a function with no production caller, four broken observation channels, and the checklist that would have
  found it in one round.
- [UI design tokens, and how a plugin's interface stays consistent with the host](./NOTES/2026-02-ui-design-tokens.md)
  — why isolation makes shared components impossible, what the host injects instead, and the two channels a theme
  change needs.
- [The feature matrix was never buildable](./NOTES/2026-02-the-feature-matrix-was-never-buildable.md)
  — an audit of what the M0 acceptance criteria assume against what the workspace contains, and why an acceptance
  criterion that cannot fail is not one.

## 许可

MIT
