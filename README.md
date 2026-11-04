# synra-core

Synra 的 Rust 内核，为设备协作和插件执行提供通用能力。
它负责发现、配对、通信、任务与传输、插件安装和授权，让桌面应用、移动端宿主与命令行复用同一套规则。

[使用文档](https://synra-app.dev/zh/guide/introduction) · [插件开发](https://synra-app.dev/zh/plugins/getting-started) · [问题反馈](https://github.com/synra-rs/synra-core/issues)

## 核心能力

- 局域网 UDP 发现、TCP 通信，以及需要接收端明确同意的配对流程。
- 设备、插件、配置和任务的持久化与状态事件。
- 文件分块传输、校验、接收决策与插件同步。
- Wasm 组件运行时、能力检查、执行预算和插件生命周期管理。
- 插件页面资源校验、会话身份与宿主调用契约。
- 注册表与静态索引的包读取、发布者密钥记录、更新判定和签名校验。
- 经过单次授权的输入会话，以及独立的平台适配器。
- 插件作者的创建、构建、验证、签名和打包工具。

核心不依赖 Tauri 或 WebView。需要在没有 UI 时仍然成立的规则由核心维护；
窗口、导航、用户确认界面及具体平台承载由宿主接入。

## 使用方式

| 入口 | 适合谁 |
| --- | --- |
| [Synra 应用](https://github.com/synra-rs/synra-app) | 希望连接设备、安装和使用插件的用户 |
| `synra-core` 等 workspace 库 | 集成内核的 Rust 宿主开发者 |
| `synra` 与 `synra-daemon` | 需要无界面宿主和本机控制通道的使用者 |
| `synra-plugin` 与 `synra-plugin-sdk` | 编写、构建和校验独立插件的作者 |

Rust workspace 与应用仍处于未发布开发阶段。源码集成应固定已审查版本，并同步宿主、SDK 与作者 CLI；
当前契约及兼容边界见 [STABILITY.md](./STABILITY.md)。

> 当前设备通信使用明文 TCP。配对和插件能力检查不等同于传输加密或密码学身份认证。

## 相关项目

[应用](https://github.com/synra-rs/synra-app)提供图形界面，
[JS 库](https://github.com/synra-rs/synra-js)提供页面类型、测试工具与主题，
[独立插件](https://github.com/synra-rs/synra-plugin-starter)组合这些能力形成具体功能。

开发环境、命令与验证入口见 [CONTRIBUTING.md](./CONTRIBUTING.md)。
设计取舍见[设计文档](https://github.com/synra-rs/design-docs)，调查记录见 [NOTES](./NOTES)。

## 许可

MIT
