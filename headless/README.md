# OpenFortiVPN Manager Headless

配置迁移、私有备份、离线升级和整组回滚见 [恢复与升级说明](../docs/recovery-and-upgrades.md)。`rollback --no-start` 恢复上一组管理器、引擎和服务文件；回滚到旧 schema 的程序前，停止服务并使用当前程序执行 `prepare-legacy-rollback`。Debian 隔离容器的真实 dpkg 安装、升级、回滚与卸载矩阵已通过，systemctl 为合成替身；真实 systemd 和网关验收仍未完成。

这是独立于桌面 App 的 Linux 无界面版本。它以 root systemd 服务运行，通过 HTTPS API 管理多个 VPN 配置；同一配置最多一个实例。当前管理器对系统网络修改采用保守独占租约：停止、清理或恢复未完成时，其他配置不能启动，即使关闭路由/DNS选项也不例外。VPN 进程异常退出时，按 3、6、12、24、30 秒退避并以最多 30 秒的间隔持续重试；主动断开、结构化认证失败和证书信任失败不会进入自动重连。仅 `tunnel_up` 代表就绪，路由或 DNS 应用失败不会显示已连接。

桌面与 headless 共用连接准入策略。只有健康、已发布的用户连接可复用；停止中、
恢复未完成、尚未发布的启动、仓库恢复/写入、服务退出及其他网络所有者都会返回
明确错误。启动自动连接也经过同一准入检查，不能把忙碌或恢复中的实例当作连接成功。

## 快速安装

系统需要 CMake、C 编译器、OpenSSL 开发包、Rust/Cargo、`pppd` 和 systemd。Ubuntu/Debian 可先安装：

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev pkg-config ppp
```

在仓库根目录执行：

```bash
./headless/scripts/install.sh
```

脚本会构建当前仓库的 `openfortivpn` 引擎和 headless Rust 程序，然后执行一次 `sudo` 安装。也可以手工构建后安装：

```bash
cargo build --manifest-path headless/Cargo.toml --release
sudo ./headless/target/release/openfortivpn-manager-headless install \
  --engine ./build/headless-engine/openfortivpn
```

`install` 会自动完成：

- 安装 CLI 到 `/usr/local/sbin/openfortivpn-manager-headless`；
- 安装引擎到 `/usr/local/libexec/openfortivpn-manager-headless/openfortivpn`；
- 创建并启用 `openfortivpn-manager-headless.service`；
- 创建 root 所有、`0700` 的配置/状态/运行目录；
- 生成 `0600` 的 Bearer token、自签 HTTPS 证书和私钥；
- 启动 HTTPS 服务，安全默认只监听 `127.0.0.1:18443`。

默认安装输出不会显示访问 token，而是提示用独立命令查看，避免 token 进入
shell、APT、dpkg 或 CI 日志。确实需要在交互式终端中立即显示时，可显式传入
`--show-token`；自动化和软件包安装应传入 `--quiet`。之后可随时查看或轮换：

```bash
sudo openfortivpn-manager-headless token
sudo openfortivpn-manager-headless token --rotate
sudo systemctl restart openfortivpn-manager-headless
```

上面的离线 CLI token 轮换在服务重启后生效；通过已授权 API 的在线 token
轮换会更新运行中的认证状态，不需要重启 HTTPS 服务或 VPN。

在浏览器打开 `https://SERVER:18443/` 后，完整 Web 控制台会先要求输入
访问 token，再显示配置编辑、连接、重连、断开、删除、实例状态和日志。
token 只保存在该浏览器标签页的 sessionStorage，并作为 Bearer token 发送；服务端
不会通过配置列表或快照 API 返回 token 或 VPN 密码。

## CLI

```bash
sudo openfortivpn-manager-headless install [--engine PATH] [--no-start] [--show-token|--quiet]
sudo openfortivpn-manager-headless uninstall [--purge]
sudo openfortivpn-manager-headless token [--rotate]
sudo openfortivpn-manager-headless status
sudo openfortivpn-manager-headless serve [--engine PATH] [--bind-address IP] [--port PORT] \
  [--experimental-control [--experimental-native-network]]
```

普通 `uninstall` 保留配置和密钥；`uninstall --purge` 会永久删除 `/etc/openfortivpn-manager-headless`、`/var/lib/openfortivpn-manager-headless` 和 `/run/openfortivpn-manager-headless`。

## 配置与远程访问

健康检查不需要 token：

```bash
curl -k https://SERVER:18443/health
```

其他 API 必须发送 Bearer token：

```bash
TOKEN=$(sudo openfortivpn-manager-headless token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://SERVER:18443/api/v1/snapshot
```

创建配置，示例请求见 [`examples/profile.json`](examples/profile.json)：

```bash
curl -k -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data @headless/examples/profile.json \
  https://SERVER:18443/api/v1/profiles
```

连接、断开、重连和删除：

```bash
curl -k -X POST -H "Authorization: Bearer $TOKEN" \
  https://SERVER:18443/api/v1/profiles/office-vpn/connect
curl -k -X POST -H "Authorization: Bearer $TOKEN" \
  https://SERVER:18443/api/v1/profiles/office-vpn/disconnect
curl -k -X POST -H "Authorization: Bearer $TOKEN" \
  https://SERVER:18443/api/v1/profiles/office-vpn/reconnect
curl -k -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://SERVER:18443/api/v1/profiles/office-vpn
```

主要兼容桌面端 API：

- `GET /health`
- `GET /api/v1/snapshot`
- `GET|POST /api/v1/profiles`
- `DELETE /api/v1/profiles/:id`
- `GET /api/v1/instances`
- `GET /api/v1/logs?instanceId=...&limit=...`
- `POST /api/v1/profiles/:id/connect|disconnect|reconnect`

`profiles` 和 `snapshot` 响应只有 `passwordStored`/`hasSecret` 布尔值，永远不会返回 VPN 密码。

## 配置文件与安全边界

| 路径 | 用途 | 权限 |
| --- | --- | --- |
| `/etc/openfortivpn-manager-headless/profiles.json` | 配置元数据，不含密码 | `0600` |
| `/etc/openfortivpn-manager-headless/secrets.json` | VPN 密码 | `0600` |
| `/etc/openfortivpn-manager-headless/access-token` | HTTPS Bearer token | `0600` |
| `/etc/openfortivpn-manager-headless/private-key.pem` | HTTPS 私钥 | `0600` |
| `/run/openfortivpn-manager-headless/*.conf` | 引擎临时配置 | `0600`，进程退出后删除 |

目录权限均为 `0700`。写入使用同目录临时文件和原子替换，并拒绝把私密文件当作符号链接读取。服务以 root 运行，因此安装完成后连接/断开 VPN 不再要求重复输入系统密码。

默认生成自签证书，首次使用可以临时配合 `curl -k`。正式远程部署建议用防火墙限制 `18443/tcp` 来源，并用受信任证书替换 `certificate.pem` 与 `private-key.pem`，保持 root 所有且权限 `0600`。证书必须覆盖 HTTPS 对外名称；域名证书可在 `server.json` 设置 `"certificateName":"console.example.com"`，它与 `bindAddress` 分开。替换证书和私钥前停止服务，完整安装匹配的 PEM 对；无效证书或不匹配的私钥会使启动失败，不会被自动覆盖。自动生成的身份在名称变化时更新，写入中断通过私有 TLS 日志恢复。

默认监听回环地址，因此另一台电脑无法直接访问。需要远程管理时，把
`server.json` 的 `bindAddress` 改成服务器的内网或 VPN 网卡地址（不建议直接
使用 `0.0.0.0`），并只在主机防火墙中放行可信来源。

修改监听地址或端口：

```bash
sudo install -m 600 headless/examples/server.json /etc/openfortivpn-manager-headless/server.json
sudo systemctl restart openfortivpn-manager-headless
```

## 验证与日志

```bash
cargo fmt --manifest-path headless/Cargo.toml --check
cargo test --manifest-path headless/Cargo.toml
sudo systemctl status openfortivpn-manager-headless
sudo journalctl -u openfortivpn-manager-headless -f
```

单元测试覆盖 Bearer 鉴权、密码不进入 API、私密文件权限、配置注入防护、
单配置单实例、多配置命令交错与存储串行化，以及有界自动重连。多配置测试
不代表多个真实 VPN 可以同时修改网络；当前仍使用保守独占租约。


### 实验性 OTP 与连接前租约

仅在隔离验收环境中使用 `serve --experimental-control` 和当前构建的引擎。
引擎经独立 stdin 管道接收绑定 attempt/request 的响应；OTP 不写入配置、
凭据或日志。认证成功后，引擎在创建适配器前等待管理器授予独占网络租约。
此模式仍只允许一个网络修改连接，不代表已支持并发网络后端或任意网关 OTP。
默认安装的 systemd 服务不会开启此选项。

授权客户端读取 `GET /api/v2/authentication/challenges`，再提交
`POST /api/v2/authentication/response`，正文为 `profileId`、`attemptId`、
`requestId`、`response`。挑战过期、旧 attempt、重复响应和停止中的连接会被
拒绝。远程页面显示当前配置的验证码输入并在提交、挑战变化或退出时清空。
取消使用现有 disconnect 操作。桌面本地/helper OTP 通道已接入并通过本地合成测试；真实 helper/网关兼容验收和 SAML 浏览器/引擎接入仍未完成。

### Linux 实验性原生路由与 scoped DNS

仅在隔离 Linux 验收环境中，使用当前构建的管理器和引擎：

```bash
sudo openfortivpn-manager-headless serve --experimental-control --experimental-native-network
```

此选项依赖私有控制通道，默认 systemd 服务不启用。引擎在创建 PPP 前协商
`grant_native`，随后发送绑定 attempt/request 的有序 route/DNS 资源。管理器
校验完整计划、接口名/index/本地地址及接口已启动，先持久化接口归属，再由
原生 worker 应用 rtnetlink 路由和 systemd-resolved scoped DNS。只有应用成功、
引擎确认并再次检查接口已启动后，才接收 `tunnel_up` 为就绪证据。

当前范围为 IPv4 direct split routes、metric 0 和 scoped DNS。路由不能覆盖
实际 VPN 传输对端（含代理对端），且必须为计划中的 DNS 服务器提供出口。
full tunnel、物理网关例外、pppd call/plugins 和 use-peerdns 配置会被拒绝。
此模式仍保留全局独占，不提供多隧道并发能力。

断开需要完成原生资源 release；清理消息本身不能释放所有权。接口消失、外部
资源替换、创建或清理结果不确定时保留事务日志和恢复记录。worker 完成 join
之前，取消请求或服务退出不能丢弃其所有权。helper/桌面原生 worker、其他平台
握手和 full tunnel 仍需开发。

遗留原生事务、孤立接口绑定、损坏记录或仍在运行的 worker 会阻止新的连接、
升级维护和人工清理确认。即使全局所有者记录已经消失，离线确认也不能删除仍受
原生恢复证据保护的本地记录；应先完成相应原生资源恢复。

最新隔离 Linux namespace 套件 30 项通过，包含真实内核路由、私有 fake
resolved D-Bus 和纯逻辑测试；未修改开发宿主网络。它不能替代真实 FortiGate、
systemd 或完整平台验收。协议细节见 [引擎控制协议](../docs/engine-control.md)。

`diagnostics --output /private/report.json` 导出离线仓库与引擎统计，文件为私有
权限；实时状态使用授权的 `/api/v2/diagnostics`。诊断报告不包含配置身份、
用户名、主机、密码、OTP、路径或原始日志。
