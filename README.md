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
> ⚠️ **尚未开始实现。** 目前只有这份 README。**动手前必须先跑 M0 的技术验证 spike**（见「下一步」）。

---

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
2. **跑 M0 的 8 个技术验证 spike**（[19 路线图 §0.1](https://github.com/synra-rs/design-docs/blob/main/19-roadmap.md)）
   —— **在写任何 crate 之前**。本机生态里没有先例的三件事：
   wasmtime 组件模型、Tauri 移动端、UDP 局域网发现。
3. 搭 workspace 与 CI（含结构守卫与 `cargo public-api` 快照）。

## 许可

MIT
