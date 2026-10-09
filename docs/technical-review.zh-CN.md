# 技术评估与问题清单

> 本文冻结评估时的代码基线与发现，下面“代码未修改”等表述描述原始评估阶段。用户随后已授权全量开发；当前实现与验证见 [任务账本](../.codex-tasks/reliability-control-plane/TODO.csv) 和 [开发进度](../.codex-tasks/reliability-control-plane/PROGRESS.md)。

评估日期：2026-10-09（Asia/Shanghai）。代码基线：`126ba3a6f3760f56dfff954a06927a0707ea2821`，当前分支 `master`，管理器版本 `0.1.6`，C 引擎版本 `1.24.1`。本次交付为调研与方案，运行时代码未修改。开发任务与验收标准见 [完整开发计划](development-plan.zh-CN.md)。

## 1. 判断与范围

项目已有可用的产品骨架：C 引擎负责隧道，Rust 负责配置、凭据和生命周期，Tauri/Svelte 与 HTTPS 页面负责交互。证书 TOFU、Unix 受限 helper、PID 身份检查、单配置启动防重、重连取消、托盘驻留及安装包 CI 都已存在，应在这些机制上继续建设。

主要不足集中在四个方面：不同平台的安全行为不一致；桌面与 headless 各自实现控制面导致语义分叉；进程状态与网络资源状态没有形成完整事务；测试能够证明组件构建成功，却没有覆盖关键交错和恢复场景。因此，建议优先进行一致性与可靠性建设。

本次审阅覆盖 `src/`、桌面 Rust 后端、Unix helper、Svelte 页面、远程 HTML、headless 的模型/存储/管理/API/安装，以及 CMake、Autotools 和 GitHub workflows。没有读取真实 VPN 密码、连接真实网关、安装系统服务或改变路由/DNS。没有核查线上 issue、远端 CI 历史或实际下载的发布附件。

证据分三类：**复现**表示在隔离目录、假引擎或提取的页面函数上执行验证；**源码**表示可以直接从控制流确认；**待验证**表示需要目标平台或真实网关。复现平台为 macOS x86_64；Linux `/proc` 身份校验、Windows 原生网络调用和真实浏览器交互没有在本次运行验证。

优先级定义：P0 为发布前必须处理的安全阻断项；P1 为可靠性与数据正确性问题；P2 为后续能力和维护性建设。优先级是工程排期建议，不代表已完成漏洞利用或 CVSS 评级。

## 2. 已运行的验证

| 验证 | 结果 | 证明范围 |
| --- | --- | --- |
| 桌面 `cargo test --locked --all-targets --all-features` | 44 个测试通过 | 当前 macOS 编译路径及现有测试 |
| helper `cargo test --locked --all-targets` | 7 个测试通过 | 配置白名单、记录、令牌与身份判断的现有测试 |
| headless `cargo test --locked --all-targets` | 19 个测试通过 | 当前平台上的存储、API 和假进程测试 |
| 三个 Rust 包的格式检查及 Clippy `-D warnings` | 通过 | 静态质量检查 |
| `pnpm check` | 0 错误、0 警告 | Svelte/TypeScript 类型与诊断 |
| CMake Debug 构建、`ctest --output-on-failure` | 构建成功，2 个测试目标通过 | PPP 状态机与 URL 编码；不是实际 VPN E2E |
| 隔离 headless 探针 | 复现进程重叠、并发保存丢失、校验分叉等 | 控制逻辑和存储，不包含平台网络副作用 |
| Node VM 执行原页面 `api`/`refresh` 函数 | 复现吞错与错误字段不一致 | 原页面函数逻辑，不等同浏览器 E2E |
| 链接实际 `src/config.c` 编译对象的探针 | 验证密码去空白及证书摘要大小写保留 | C 配置解析行为 |

基线命令在仓库根目录执行：

```sh
rtk cargo test --locked --manifest-path app/src-tauri/Cargo.toml --all-targets --all-features
rtk cargo test --locked --manifest-path app/src-tauri/helper/Cargo.toml --all-targets
rtk cargo test --locked --manifest-path headless/Cargo.toml --all-targets
rtk cargo clippy --locked --manifest-path app/src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
rtk cargo clippy --locked --manifest-path app/src-tauri/helper/Cargo.toml --all-targets -- -D warnings
rtk cargo clippy --locked --manifest-path headless/Cargo.toml --all-targets -- -D warnings
rtk proxy zsh -c 'cd app && pnpm check'
rtk proxy cmake -S . -B /tmp/openfortivpn-audit-20261009-cmake -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug
rtk proxy cmake --build /tmp/openfortivpn-audit-20261009-cmake --parallel 4
rtk proxy ctest --test-dir /tmp/openfortivpn-audit-20261009-cmake --output-on-failure
```

格式检查分别使用 `cargo fmt --manifest-path <manifest> --all -- --check`。仓库没有可复用的 `.claude/scripts/verify-*.sh`，也没有落盘的 AGENTS/CLAUDE harness 文件；已遵循本次会话提供的规则及全局 RTK 规则。

探针保存在本机 `/tmp/openfortivpn-audit-20261009-probes/`，包含 Rust 控制/存储探针、页面函数探针、C 配置探针。最终 Rust 探针复制了仓库 headless 的 lockfile 作为解析起点，使用本地 headless path dependency 和离线构建。临时目录不是项目长期回归测试的替代品；开发计划 M0 要将这些场景转为仓库测试。

## 3. 优先级总表

| 编号 | 优先级 | 问题 | 证据 | 主要影响 |
| --- | --- | --- | --- | --- |
| F01 | P0 | Windows TLS 缺少主机名校验，`insecure_ssl` 语义分叉 | 源码 | 错误身份的受信证书可能被接受 |
| F02 | P1 | headless 停止中可重新启动、修改同一配置 | 复现 | 同配置同时存在两个进程 |
| F03 | P1 | headless 配置保存缺少并发串行化 | 复现 | 成功返回的写入仍可能丢失 |
| F04 | P1 | 密码和会话凭据契约不同 | 复现、源码 | 认证失败、功能行为不一致 |
| F05 | P1 | 多 VPN 没有全局路由/DNS 仲裁 | 源码 | 连接间互相影响，清理顺序不安全 |
| F06 | P1 | 连接就绪、错误事件和退出码缺少统一契约 | 源码 | 显示已连接但网络未就绪，错误重试 |
| F07 | P1 | headless 启停清理与服务期限不闭合 | 源码 | 异常路径、强制终止时资源恢复不明确 |
| F08 | P1 | Web 登录吞错、两套 API 与删除语义不同 | 复现、源码 | 假成功界面、泛化错误、删除失败 |
| F09 | P2 | headless TLS 身份不跟随地址变化，IPv6 拼接错误 | 复现 | 换监听地址后证书不匹配，IPv6 无法启动 |
| F10 | P1 | 凭据与配置更新缺少跨资源恢复事务 | 源码 | 失败后内存、配置、凭据不一致 |
| F11 | P2 | 管理器没有 OTP/SAML 等认证交互模型 | 源码 | C CLI 能力无法完整用于 GUI/service |
| F12 | P2 | 特权与凭据策略需要进一步收敛 | 源码、设计 | Windows UI/headless HTTPS 仍有完整系统权限 |
| F13 | P2 | 重复控制面与大文件提高修改成本 | 源码 | 修复无法自然覆盖所有入口 |
| F14 | P1 | 核心场景与组合变更缺少持续回归门槛 | 源码 | 当前测试未能发现已复现问题 |
| F15 | P2 | 日志、实例历史、快照与诊断缺少容量模型 | 源码 | 长期运行资源增长、轮询成本、排障困难 |
| F16 | P2 | 依赖、签名发布与工程上下文门槛仍不完整 | 源码 | 发布标识与实际验证可能偏离 |

## 4. 具体发现

### F01：Windows TLS 身份校验（P0）

位置：[Windows TLS](../src/tunnel_win.c) 243、336 行；对比 [Unix 校验](../src/tunnel.c) 870、893 行。

Windows 在握手后读取 `SSL_get_verify_result`，当结果为 `X509_V_OK` 时直接通过，没有验证证书是否属于 `gateway_host`。SNI 只用于选择服务端证书，不能替代身份校验。Unix 路径显式要求 `X509_check_host(...) == 1`。Windows 的 `insecure_ssl` 还会跳过整个证书校验块；Unix 的同名设置主要调整协议/密码策略，仍执行 `ssl_verify_cert`。

方案：抽出共同的证书校验策略，明确 CA 链、DNS 名/IP SAN、精确指纹信任的关系，检查 OpenSSL 返回值。保留现有 TOFU 语义，通过验证回调或握手后独立验证来获取失败证书，不能因为提前中断握手而丢失 `cert_error`。`insecure_ssl` 的兼容含义须写入迁移说明，禁止成为管理器隐式绕过身份检查的开关。

验收：有效 CA 但主机名错误、错误 IP SAN、过期/未知 CA、无证书、错误指纹均进入预期拒绝路径；正确身份与明确确认的 pin 通过。必须在 Windows 构建路径上执行。这是源码确认的缺陷，本次没有进行 Windows 网络攻击复现。

### F02：headless 生命周期互斥窗口（P1）

位置：[管理器](../headless/src/manager.rs) 178、227、293、589、787 行。

`disconnect` 在确认退出之前将 `desired=false` 并取走 `process`。`connect` 只依据 `desired` 判重；`is_active` 同样只检查该字段。假引擎在 SIGTERM 后延迟两秒退出时，新连接和配置修改均被接受，并测得同一配置的两个 PID 同时存活。

`stop_owned_process` 超时发送 SIGKILL 后即返回，未等待最终退出与收割。`finish_failed` 在判断实例 ID 之前清理 profile control，也应补充 generation/attempt 身份检查，避免旧任务作用到新控制状态；后一条属于源码风险，未单独复现。

方案：短期引入明确的 `Stopping` 与逐配置操作预约；长期用 profile actor 串行处理命令。保留旧 child/supervisor handle，直到 `wait`、输出读取、清理结果全部完成。取消重试只改变用户意图，不能释放运行中实例的所有权。

### F03：headless 并发写入丢失（P1）

位置：[存储](../headless/src/storage.rs) 119、147、161、305 行；[管理器保存入口](../headless/src/manager.rs) 163 行。

保存过程为“读取所有 profiles/secrets → 修改 → 分别原子替换”。单文件原子 rename 不提供读改写事务。隔离探针同时保存 16 个不同配置，16 次调用均成功，最后仅保留 1 个新增配置。实际服务的 Tokio 多线程可同时执行这些同步操作；CLI 与服务也没有共同的写入锁。

方案：紧急修复为覆盖完整读改写的进程内锁，并对跨进程写入加锁或将在线 CLI 写入统一送到服务。中期采用 versioned repository + revision/CAS；headless 可用 SQLite 事务同时保存 profile 与 secret reference，桌面保持平台凭据适配器。禁止将文件原子写等同于并发事务。

### F04：密码与会话凭据分叉（P1）

位置：[桌面密码校验](../app/src-tauri/src/lib.rs) 627 行；[headless 保存/运行配置](../headless/src/storage.rs) 119、251 行；[C 解析](../src/config.c) 221、259 行；[字段长度](../src/config.h) 58 行。

桌面拒绝密码首尾 ASCII 空白、NUL 和超过 256 字节；headless 接受上述四类输入。C 文件解析会去空白、按固定长度截断，NUL 影响 C 字符串长度。因此“保存的密码”可能不等于“参与认证的密码”。探针也确认 `rememberPassword=false` 时 headless 丢弃传入密码，`hasSecret=false` 且不能连接；桌面支持当前会话密码。

方案：共用按 UTF-8 字节计数的 `SecretInput` 与校验器，覆盖用户名/Realm/host 等 C 定长字段。统一 `keep/replace/delete/session` 意图，避免空字符串承担多种含义。headless 可明确不支持会话凭据并返回 capability/校验错误，也可提供内存凭据；不能静默成功。长期如需支持密码首尾空格，应修改引擎输入协议保留原值，而不是在 UI 自动 trim。

### F05：网络资源没有统一所有权（P1）

位置：[并发支持边界](architecture.md)、[Unix 路由/DNS](../src/ipv4.c) 958、1052、1099、1315 行、[Windows 路由/DNS](../src/ipv4_win.c) 254、342、425 行。

现有文档提示非重叠 split route，并明确全局仲裁超出安全边界；控制面却允许多个配置同时启用路由和 DNS，默认新配置两者都启用。引擎各自记录、修改和恢复系统网络状态，Unix 直接写 resolv.conf 的路径没有跨引擎所有权管理。两个 profile 也可能命中相同网关、相同目的网段或相同 DNS。

方案：先在控制面实施保守的网络修改互斥，并覆盖启动、自动连接、自动重连和所有 API。对旧引擎无法获知路由计划的情况，不能宣称可安全并发。随后在引擎实际修改网络之前引入 `network_plan → lease decision → apply → ready` 协议，让全局 coordinator 管理路由/DNS 租约与引用计数。各平台独立进程中的 C 静态变量不应被误判为跨进程共享内存问题；真正冲突对象是系统网络资源。

### F06：就绪状态与错误策略分叉（P1）

位置：[headless 事件映射](../headless/src/manager.rs) 494 行、[桌面映射](../app/src-tauri/src/lib.rs) 1372 行、[Windows 提前 connected](../src/tunnel_win.c) 635 行、[接口协商](../src/io_win.c) 397 行、[退出码](../src/exit_codes.h)。

headless 将 `tunneling` 也映射为 Connected，此时 PPP 可能尚未就绪。Windows 在进入 `io_loop` 前发出 `connected`，PPP 协商和网络配置随后才进行。桌面为此保持 Connecting，直到 tunnel_up，说明两套消费者已有不同补救逻辑。

另外，两平台路由/DNS 错误可能仅输出 warning 后仍发 tunnel_up；Windows DNS 的 `system(cmd)` 返回值被忽略。Unix 的多个失败分支仍返回 generic，而 Windows 使用分类退出码。两个 Rust 管理器还用英文日志片段识别认证失败；桌面 monitor 仅等待 100ms 给输出线程处理，不能保证错误分类已经完成。

方案：版本化事件协议，显式 `reasonCode/retryable/phase`；只有实际网络就绪才发 ready。输出流完成必须通过 join/EOF 确认，不用固定 sleep 猜测。对网络配置失败选择显式失败或 Degraded；必须让用户知道路由/DNS 是否成功。

### F07：服务启动失败与关闭期限（P1）

位置：[headless serve](../headless/src/lib.rs) 40、69 行、[shutdown](../headless/src/manager.rs) 273 行、[systemd unit](../headless/src/install.rs) 108 行。

headless 在验证 TLS 配对、成功 bind 服务之前调用 auto-connect，后续 `?` 错误可跳过 `manager.shutdown`。shutdown 顺序停止每个进程，忽略 stop 错误；unit 的 `TimeoutStopSec=15s` 与 HTTPS graceful drain 的 10s、多个进程各自 5s 的停止期限不能保证兼容。强制杀死 C 进程可能绕过正常路由/DNS 恢复。

方案：先获得完整服务资源，再开放自动连接；用 scope guard/结构化任务确保所有退出路径都会进入关闭流程。关闭采用全局 deadline、逐连接并发收敛、错误汇总与恢复 journal。headless 还需单服务目录锁和重启恢复协议；systemd cgroup 清进程不能替代网络资源恢复。

### F08：远程页面与 API 契约（P1）

位置：[页面](../app/src-tauri/src/remote.html) 51、63、67、69 行、[headless API](../headless/src/api.rs) 46、108、193 行、[桌面 API](../app/src-tauri/src/remote.rs) 326 行、[桌面删除](../app/src-tauri/src/lib.rs) 1894 行。

`refresh` 捕获错误后正常 resolve，登录调用者仍执行“显示 app、保存 token、开始轮询”。VM 探针给出 `invalidTokenRefreshResolved=true`。这会导致界面假成功，后端仍校验 token，不能据此声称认证被绕过。轮询静默失败也没有明确的离线状态。

页面读取错误字段 `.error`，headless 返回 `.message`，实际错误被显示为泛化的“请求失败 (400)”。页面提供“断开并删除”，桌面后端会停止再删除，headless 却拒绝删除活动配置。桌面使用中文错误子串映射 HTTP 状态，headless 大部分管理错误统一 400。

方案：统一结构化错误、操作语义与 capability；登录使用严格失败传播，轮询使用单请求与取消机制。v1 过渡期兼容 error/message；需要破坏性调整时新增 v2。删除策略统一为显式 `stopAndDelete` 或明确 409 的只删静止配置，UI 按实际能力呈现。

### F09：headless HTTPS 地址与身份（P2）

位置：[证书](../headless/src/storage.rs) 221 行、[地址构造](../headless/src/lib.rs) 34 行，对比 [桌面证书名称记录](../app/src-tauri/src/remote.rs) 256 行。

证书/私钥只要存在就被复用；隔离探针从 loopback 改为 `192.0.2.123` 后证书内容未改变，新地址没有对应 SAN。`format!("{}:{}", bind, port)` 对 `::1` 构造出 `::1:18443`，SocketAddr 解析失败。证书和私钥分两次写入也缺少一组身份的提交标记。

方案：用 `IpAddr + SocketAddr::new`，共用 SAN 元数据与 TLS identity generation，验证证书/私钥匹配后切换。token 轮换目前需要重启服务，文档已说明；后续可独立热轮换，避免把令牌轮换绑定到所有 VPN 重启。

### F10：存储事务与失败恢复（P1）

位置：[桌面保存](../app/src-tauri/src/lib.rs) 1838、1868 行、[删除](../app/src-tauri/src/lib.rs) 1910 行、[持久化](../app/src-tauri/src/lib.rs) 429 行、[远程设置写入](../app/src-tauri/src/remote.rs) 129 行；headless 见 F03。

桌面先更新/删除系统凭据，再持久化 profile；失败时可能改变了凭据而 profile 未更新。删除还先清运行内存，再持久化文件。Windows profiles 使用直接 fs::write，远程 settings 也直接覆盖，损坏/中断路径缺少统一恢复语义。Unix 虽有 temp+fsync+rename，但跨文件与凭据后端仍不是事务，父目录持久化也应纳入断电模型。

方案：定义 repository commit revision、backup 与迁移版本；平台凭据采用新 reference + 操作 journal/saga，提交成功后回收旧 reference。失败返回时保持旧状态，或明确标记 RecoveryRequired，启动时可收敛。不能假定 OS credential store 可与 SQLite 做一个 ACID 事务。

### F11：认证能力未贯通管理器（P2）

位置：[模型](../app/src-tauri/src/lib.rs) 40 行、[headless 模型](../headless/src/model.rs) 12 行、[关闭 stdin](../app/src-tauri/src/lib.rs) 2328 行、[headless 子进程](../headless/src/manager.rs) 384 行、[OTP/SAML](../src/http.c) 444、653、774 行。

C CLI 已有 OTP、SAML/cookie、客户端证书等路径，管理器 model 只有密码等基本字段，又以空 stdin 启动引擎，缺少认证挑战回应通道。客户端证书选项也不在当前 helper 的普通配置白名单中。不能通过开放任意引擎配置或 pppd-plugin 来补功能。

方案：增加 `AuthMethod`、typed challenge 与单次 response 通道，明确交互认证不进行无人值守无限重试。SAML 回调校验 state、精确路径、一次性有效期与取消；浏览器认证由低权限客户端执行。客户端证书只允许受控安装的 credential reference。

### F12：特权与凭据策略（P2，属于设计取舍）

位置：[Windows manifest](../app/src-tauri/windows-app-manifest.xml)、[root service](../headless/src/install.rs) 108 行、[macOS 凭据](../app/src-tauri/src/lib.rs) 506 行与 [架构说明](architecture.md)。

Unix helper 已明显缩小提权边界，应该保留。Windows 整个 GUI/WebView 以管理员启动，headless HTTPS 解析与业务服务也运行为 root。macOS 的 0700/0600 明文凭据是已披露的签名兼容策略，应视为现有政策而非未披露泄漏。单个高熵 Bearer token、默认 loopback、无开放 CORS 也是有效基础；单管理员产品当前不必立即引入多租户/RBAC。

方案：稳定签名的正式 macOS 渠道恢复可选择的系统凭据存储，并显式迁移；内部 ad-hoc 渠道保留现有政策。后续 Windows service/named pipe ACL、Linux 非特权控制面 + 窄 helper 都需要单独的威胁模型与平台测试。不会仅靠“加密文件”解决同用户进程可读的问题。

### F13：重复控制面与模块边界（P2）

桌面 `lib.rs` 4402 行、`remote.rs` 848 行、Svelte 单页面 1968 行；headless 另有 1065 行 manager 与 479 行 storage。模型、校验、重连、API、TLS 都存在重复。headless 还通过相对路径直接 include 桌面 `remote.html`，其共享范围仅是页面，未保证行为契约。

方案：建立轻量 Cargo workspace，将 domain、protocol、repository、lifecycle、HTTP 契约抽为纯 Rust crate。Tauri tray/keyring/platform UI 保留在 adapter。抽取先从模型和校验开始，每次迁移一个边界并跑双入口契约测试；避免先做大范围文件搬迁，之后再补行为测试。

### F14：验证覆盖与触发范围（P1）

位置：[App CI](../.github/workflows/app.yml)、[Headless CI](../.github/workflows/headless.yml)、[Release](../.github/workflows/app-release.yml)、[C tests](../CMakeLists.txt) 261 行。

App CI 在常规检查中跳过真实引擎构建；路径过滤没有覆盖 C 代码。headless CI 也不因 C 引擎变更运行自身测试/包构建。发布 workflow 已有组合质量门槛和安装烟测，不能说项目没有 CI；但烟测主要证明应用/服务启动，没有自动验证真实连接、网络回收、TOFU、托盘、错误登录和并发写入。C 自动测试集中在 PPP/URL 两个目标，Windows TLS、Unix helper 实际提权生命周期与路由/DNS 事务没有等价覆盖。

方案：分为快速纯逻辑回归、假进程组合、隔离 OS 网络集成、受控网关兼容四层。共同变更与 C 变更必须触发消费者验证；正式发布读取各层证据。无需把所有真实 VPN 测试放入普通 PR 环境。

### F15：容量与可观测性（P2）

位置：[desktop 实例保存](../app/src-tauri/src/lib.rs) 2403 行、[日志读取](../app/src-tauri/src/lib.rs) 1451 行、[headless 日志](../headless/src/manager.rs) 469 行、[snapshot](../app/src-tauri/src/remote.rs) 408 行。

日志按条数保留，没有按字节和单行长度限制。桌面重连不断创建新 instance，直到删除 profile 才整体清理；远程页面每两秒拉完整 snapshot。桌面 snapshot 还会启动 engine --version 和执行 privilege check；headless EngineInfo.version 则直接使用管理器版本，没有验证实际引擎版本。前端用“实例+秒时间戳+流+内容”去重会合并同秒重复日志。

方案：结构化 event ID、字节预算、实例 TTL/分页、元数据缓存与有限诊断包；推送可使用带 cursor 的 SSE，但当前前端使用 Bearer header，需 fetch streaming 或短时 stream ticket，不能把长期 token 放 URL。补充网络 ready/cleanup outcome/重连原因和操作审计，基准测试后确定容量上限。

### F16：依赖与发布治理（P2）

位置：[Dependabot](../.github/dependabot.yml)、[CodeQL](../.github/workflows/codeql-analysis.yml)、[签名分支与 publish](../.github/workflows/app-release.yml) 182、392、645 行、[构建脚本](../app/scripts/build-engine.mjs) 62 行、[SECURITY](../.github/SECURITY.md)。

Dependabot 目前只覆盖 Actions，CodeQL 选择 cpp，没有与 Rust/前端依赖更新相配套的自动门槛。发布正常/预发布由 `OFFICIAL_SIGNED_RELEASE` 决定，缺少签名 secrets 时构建仅 warning；若该变量配置错误，可出现“正常发布”标识与签名事实不一致。release notes 又固定声明 secrets 未配置。helper 本地 build 没有 --locked，多个版本来源缺少一致性检查。SECURITY 仍指向上游地址，需要确认此 fork 的责任人和响应路径。

方案：验证正式签名、公证、附件清单后才生成 verified release manifest；缺少任何正式门槛即失败或保持预发布。添加依赖扫描/许可证检查、SBOM、来源记录、版本一致性脚本；保护发布权限并按 job 最小化写权限。维护本仓库准确的安全支持与贡献流程。GitHub branch protection、secrets 与负责人实际配置不在本次已验证范围。

## 5. 复现结果摘录

```text
password_leading_space_accepted=true
password_trailing_space_accepted=true
password_nul_accepted=true
password_257_bytes_accepted=true
session_password_has_secret=false
session_password_connectable=false
certificate_unchanged_after_bind_change=true
ipv6_default_format_parse_ok=false
concurrent_profile_saves=16, retained=1
profile_mutation_accepted_during_stopping=true
new_connect_accepted_during_stopping=true
two_same_profile_processes_alive=true
invalidTokenRefreshResolved=true
headlessErrorShown="请求失败 (400)"
leading_trailing_spaces_removed=1
uppercase_pin_preserved=1
```

最后一条说明 C 配置保留大写 pin，而 Unix 校验用小写摘要与 memcmp；管理器校验接受大小写十六进制。应在公共校验器规范化 pin，并加入大小写等价测试。这是附属兼容性问题，不应与 F01 的主机名身份缺陷混为一谈。

假引擎只输出 tunnel_up、等待与响应 SIGTERM，未执行 PPP 或任何网络命令。并发写入探针使用 16 个线程同时调用真实 Storage.save_profile；保留数量依调度可能变化，验收目标必须是始终保留全部成功写入。页面探针使用原文件中的函数，并模拟 401/400 响应。

## 6. 还需要目标环境确认的事项

| 项目 | 后续验证方法 | 本次结论边界 |
| --- | --- | --- |
| Windows 系统 CA 与打包 OpenSSL 的 trust store | 干净 Windows VM，受控 CA/自签/错主机名服务 | 尚未验证默认 CA 是否可用 |
| pppd 版本及平台选项差异 | Linux 2.4/2.5、macOS 实际连接矩阵 | CMake legacy 默认为 0；不能仅据此声称 macOS 无法连接 |
| FortiGate 各认证/策略版本 | 独立测试账号与测试网关 | 不承诺所有网关模式兼容 |
| 真实路由/DNS 恢复 | 保存基线，A/B 并发、任意退出顺序、断网、崩溃与重启 | 源码已见所有权缺口，实际损坏场景待隔离 OS 验证 |
| C HTTP/XML/HDLC/PPP 输入健壮性 | ASan/UBSan + 有长度上限的 fuzz harness | 未做完整内存安全审计，不声称已证明内存漏洞 |
| 实际发布包签名、公证与依赖动态库 | 下载候选附件，在干净 OS 安装并核验 | 本次仅审阅发布脚本 |

## 7. 推荐决策

选择“保留引擎与 UI 技术栈、先补可靠性、渐进共用控制面、分阶段仲裁网络资源”。首轮必须关闭 F01—F08、F10、F14 中的核心问题，同时快速处理 F09。OTP/SAML、全平台 split DNS、Windows 权限分离、完整 IPv6 数据面属于后续里程碑，不能与修复阻断项混在一次大改中。

后续是否宣布正式生产版本，应依据目标平台的验收证据和声明的支持范围决定。当前测试通过能说明已有基础稳定，不能证明已复现的可靠性问题不存在。
