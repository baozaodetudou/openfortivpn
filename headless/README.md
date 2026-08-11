# OpenFortiVPN Manager Headless

这是独立于桌面 App 的 Linux 无界面版本。它以 root systemd 服务运行，通过 HTTPS API 管理多个 VPN 配置；同一配置最多一个实例，不同配置可以并行连接。VPN 进程异常退出时，按 3、6、12、24、30 秒退避并以最多 30 秒的间隔持续重试；主动断开、认证失败和证书信任失败不会进入自动重连。

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

token 轮换后需重启服务才生效。

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
sudo openfortivpn-manager-headless serve [--engine PATH] [--bind-address IP] [--port PORT]
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

默认生成自签证书，首次使用可以临时配合 `curl -k`。正式远程部署建议用防火墙限制 `18443/tcp` 来源，并用受信任证书替换 `certificate.pem` 与 `private-key.pem`，保持 root 所有且权限 `0600`。

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

单元测试覆盖 Bearer 鉴权、密码不进入 API、私密文件权限、配置注入防护、单配置单实例、多配置并行以及有界自动重连。
