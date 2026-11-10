# 内核开发

## 环境

使用 [rust-toolchain.toml](./rust-toolchain.toml) 固定的开发工具链。
最低支持 Rust 版本由根 Cargo.toml 声明，MSRV 与开发工具链分别检查。
应用、JS 库和独立插件均为其他仓库，不复制或嵌入本 workspace。

```sh
rustup toolchain install --no-self-update
cargo check --locked -p synra-core
```

## 常用入口

```sh
cargo run --locked -p synra-cli -- --help
cargo run --locked -p synra-daemon -- --help
cargo run --locked -p synra-plugin-cli -- --help
```

CLI 通过本机控制通道访问运行中的 daemon；daemon 与 CLI 使用同一数据目录。
应用则在进程内承载核心，不能假定它与另一个 daemon 共用运行状态。

## 验证

先运行受影响 crate 的测试和编译，再执行适用的阶段检查：

```sh
cargo test --locked -p synra-core --lib
cargo clippy --locked -p synra-core --lib --no-deps -- -D warnings
cargo run --locked -p guards -- .
cargo run --locked -p synra-error-guard -- .
cargo run --locked -p doc-links -- .
cargo run --locked -p doc-claims -- . .
```

完整 feature 矩阵及 Wasm、跨平台和 MSRV 作业见 [.github/workflows](./.github/workflows)。
只验证无默认功能的逻辑不代表其他宿主或平台已通过验收。

## 插件契约

WIT 是宿主导入与能力标注的来源。修改时同步生成资源、SDK、作者 CLI、实际宿主与 JS 类型。
独立插件将 SDK 和作者 CLI 固定到同一个已审查提交；使用真实组件和实际安装入口验证。

接口与数据格式的开发期约定见 [STABILITY.md](./STABILITY.md)。
编辑、锁作用域、测试及提交规则见 [AGENTS.md](./AGENTS.md)，调查证据保留在 [NOTES](./NOTES)。
