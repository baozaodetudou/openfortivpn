# OpenFortiVPN Manager 中文用户指南

OpenFortiVPN Manager 是 `openfortivpn` 的跨平台图形管理器，支持 Linux、
macOS 和 Windows。Linux 服务器还可以使用不依赖桌面的 headless 版本。

## 下载与安装

从 [GitHub Releases](https://github.com/baozaodetudou/openfortivpn/releases)
下载与系统对应的附件：

| 系统 | 附件 | 安装方式 |
| --- | --- | --- |
| Apple Silicon Mac | `macOS-arm64` | 打开 DMG，将 App 拖入 `/Applications` |
| Intel Mac | `macOS-x86_64` | 打开 DMG，将 App 拖入 `/Applications` |
| Windows x64 | `.msi` 或 NSIS `.exe` | 运行安装器，启动时允许 UAC 提权 |
| Ubuntu/Debian 桌面 | Linux `.deb` | `sudo apt install ./openfortivpn-manager_*.deb` |
| Linux 无界面服务器 | headless `.deb` 或 `.tar.gz` | 安装 DEB，或解压后运行 `sudo ./install.sh` |

预发布附件可能没有 Apple 公证或 Windows Authenticode 签名。请核对 Release
页面和 `SHA256SUMS-*.txt`，只从本项目 Release 页面下载。

## 第一次启动

1. 打开应用，选择“添加配置”。
2. 填写配置名称、VPN 地址、端口、用户名和 VPN 密码。
3. “保存到系统凭据存储”默认启用。密码会进入 macOS Keychain、Windows
   Credential Manager 或 Linux Secret Service；`profiles.json` 只记录
   `passwordStored` 状态，不记录密码明文。
4. 点击“连接”。Linux/macOS 第一次会要求一次电脑管理员密码，用于安装
   root 所有的受限 helper 和配套 VPN 引擎；该密码不会保存。
5. helper 安装后，正常连接、断开、重连、自动重连和重新启动应用都不再要求
   管理员密码。只有升级或修复 helper 时才会再次授权。

电脑管理员密码和 VPN 密码是两套凭据。前者只安装 helper，后者属于具体 VPN
配置。

## 自签证书

第一次连接自签证书网关时，应用会自动从引擎事件中取得 SHA-256 指纹并显示
确认框，不需要先去命令行查找。确认前不会保存或信任证书。应尽量通过独立可信
渠道向 VPN 管理员核对指纹；指纹变化时不要直接接受。

## 配置与连接规则

- 一个配置最多运行一个实例，重复点击不会创建第二个实例。
- 不同配置可以同时连接，分别拥有状态、日志、密码和重连策略。
- 两个 VPN 若同时修改默认路由或全局 DNS，仍可能产生操作系统级冲突；并发时
  建议使用不重叠的分流路由。
- 连接期间不能编辑或删除该配置；先断开，等待清理完成后再操作。
- “重新连接”会先完整停止旧进程，再启动新实例。
- “自动重新连接”只处理异常断开，使用 3 到 30 秒的有界退避持续重试。
  主动断开、认证失败和证书信任失败不会自动重试。

## 开机启动与自动连接

“登录时启动应用”是全局设置；“应用启动后自动连接”是每个配置独立设置。
自动连接要求该配置已把 VPN 密码保存到系统凭据存储。仅开启应用自启动不会自动
连接 VPN，仅开启配置自动连接也不会让尚未启动的应用自行运行。

## 远程 Web 管理

桌面版和 headless 版都提供 HTTPS Web 控制台。默认关闭或只监听
`127.0.0.1:18443`。启用后会生成 256 位 token 和自签 HTTPS 证书：

- token 存储在系统凭据存储或 root-only 文件中；
- 浏览器只把 token 保存在当前标签页的 `sessionStorage`；
- API 不返回 VPN 密码或 token；
- 远程端不能提交电脑管理员密码，也不能确认新的 VPN 证书指纹。

远程使用时应绑定明确的内网地址，通过防火墙限制来源，或放在可信反向代理、
私有组网之后。不要直接把 `0.0.0.0:18443` 暴露到互联网。

## Linux headless 快速使用

安装后服务会自动启动：

```bash
sudo systemctl status openfortivpn-manager-headless
sudo openfortivpn-manager-headless token
sudo openfortivpn-manager-headless status
```

浏览器访问 `https://SERVER:18443/` 并输入 token。默认仅本机可访问；远程部署、
API、配置文件和卸载方法见 [headless README](../headless/README.md)。

## 常见问题

### 为什么升级后又要求管理员密码？

应用会校验 helper 和引擎哈希。版本升级改变了系统组件，必须重新授权一次；同一
版本的日常启动和连接不会重复询问。

### 为什么密码不直接写进 profiles.json？

`profiles.json` 会被备份、同步或用于排障，写入明文密码会造成不必要的泄露。
应用把 VPN 密码交给操作系统凭据存储，并只在配置文件里记录“已保存”状态。
普通启动不会逐个读取所有密码；连接该配置或启动自动连接时才按需读取。

如果选择“不保存”，密码只在本次应用会话中有效。下次连接时会显示独立的 VPN
密码输入框，不需要重新编辑服务器、端口等整份配置。

### 为什么异常断开后没有重试？

检查该配置是否开启自动重新连接。认证错误、未知证书或用户主动断开会停止重试，
需要先修正配置或确认指纹。

### 如何确认已经完全断开？

界面应显示“已断开”，对应实例停止。Linux/macOS 可以同时检查 VPN 接口、路由
和 DNS 是否恢复；应用退出时也会等待 helper 清理整个 VPN 进程组。

### 配置和密码在哪里？

配置元数据位于操作系统的应用数据目录。VPN 密码位于系统凭据存储，不在配置
JSON 中。headless 的具体 root-only 路径和权限见
[headless README](../headless/README.md#配置文件与安全边界)。

## 更多文档

- [桌面端技术说明](../app/README.md)
- [Linux 安装与诊断](linux.md)
- [系统架构与安全边界](architecture.md)
- [构建、发布、升级和回滚](release.md)
