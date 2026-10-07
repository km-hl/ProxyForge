# ProxyForge Agent 安装与恢复（中文）

[English](README.md)。Agent 当前软件版本为 **0.6.0**，仅依赖系统 Python 3.9+ 标准库；Controller 镜像为 Python 3.12，源码 CI 覆盖 3.12/3.13，二者运行环境独立，见[运行时矩阵](../docs/PYTHON_RUNTIME.md)。

Agent 主动通过 HTTPS 上报清单、发送心跳、领取允许列表内的任务，不打开入站网络监听。普通安装不启用 root helper；管理员可在本机单独启用 Unix socket helper，管理一个独立的 sing-box 实例。清单、任务、runtime、Reality 部署、SS2022 落地和链路协议分别为 1，并分别受能力门控。升级顺序始终是 Controller 在前，Agent/helper 在后。

## 首次安装与平台边界

安装器允许 Debian 12/13、Ubuntu 22.04/24.04，amd64/arm64、systemd、Python 3.9+，拒绝其他组合。该允许列表不表示所有组合都完成了空白主机安装实测。当前是源码 Agent，没有签名二进制发行包或自动升级功能。

从官方仓库取得并审查固定完整提交后，在 **root 控制、其他用户不可写**的 checkout 中执行：

```bash
sudo bash agent/install.sh https://your-controller.example
sudo systemctl status proxyforge-agent.service --no-pager
```

这里的相对路径命令以已有可信 checkout 为前提；固定产物构建与校验见[安装产物说明](../docs/AGENT_ARTIFACTS.md)。完整下载/bootstrap/控制台复制命令仍在开发计划第 16 项，不提供不存在的 Release 地址，也不能只下载依赖相邻文件的 `install.sh`。Controller 地址必须是可信的 HTTPS 根地址，不含用户名、密码、查询参数或片段。

在 Controller **Agent 服务器 → 添加服务器**生成一次性注册 token，在安装器隐藏提示中粘贴。有效期 10 分钟，只能注册一个 Agent。不要将 token 放进命令参数、URL、shell 历史、日志、Git、截图或浏览器持久存储。

安装器创建无特权用户 `proxyforge-agent`，将包复制至 `/opt/proxyforge-agent/agent`，凭据写入 `/etc/proxyforge-agent/config.json`（目录 0700、文件 0600），启用 `proxyforge-agent.service`。已有安装会被拒绝覆盖。默认只使用系统 CA；私有 CA 需要手动注册时传入 `--ca-file /path/to/ca.pem`，并保证服务用户可读，不能关闭 TLS 验证。

服务启动后，在 Controller 核对已收到心跳；`systemctl` 成功不等于公网注册链路已验收。

## 可选托管 runtime、部署与链路

普通 Agent 安装完成后，使用**同一可信提交**的完整源码，在确认[托管运行环境说明](../docs/AGENT_B3.md)后显式执行：

```bash
sudo bash agent/install-runtime.sh
sudo systemctl status proxyforge-runtime.socket --no-pager
```

这会启用本机 root helper；不会接管已有 sing-box，也不会修改防火墙。不要仅创建能力标记以解锁动作，必须同时更新所有模块和对应 systemd unit。

- 直连 VLESS Reality：在 **Agent 服务器 → 部署**填写公网端点、SNI、端口；首次部署按需安装固定 sing-box，成功后发布只读客户端节点。见 [B4 部署与恢复](../docs/AGENT_B4.md)。
- SS2022 落地：同一对话框选择 **SS2022 落地**；至少需要 Agent 0.5.0 与对应 helper。密码由控制面生成和保管，落地不会直接成为客户端订阅节点。见 [B5a](../docs/AGENT_B5_LANDING.md)。
- 链路：Agent 0.6.0 可创建经过已就绪 SS2022 落地的独立 Reality 入口，并保留原直连入口。完整升级入口 helper 和模块后才启用 root 所有的 `chain-protocol` 标记。见 [B5b](../docs/AGENT_B5_CHAIN.md)。

## 注册失败与恢复

注册不会自动重试。若 Controller 已提交注册，但响应丢失或本地凭据保存失败，界面可能出现从未心跳的孤立 Agent；先移除该记录，再生成**新 token**。

失败安装可能已留下用户、包和 unit，不要再次运行首次安装器覆盖它们。从已检查的安装目录，以服务用户完成注册：

```bash
cd /opt/proxyforge-agent
read -r -s -p 'New registration token: ' registration_token
printf '\n'
printf '%s\n' "$registration_token" | sudo -u proxyforge-agent /usr/bin/python3 -m agent.main \
  --config /etc/proxyforge-agent/config.json register \
  --server https://your-controller.example --token-stdin
unset registration_token
sudo systemctl daemon-reload
sudo systemctl enable --now proxyforge-agent
```

待注册配置不含 token；已有完整凭据时，注册会拒绝覆盖。重新登记之前需显式撤销旧 Agent，私密归档并由管理员处理旧配置。排障不要分享该配置。

## 运行与排障

- 正常心跳每 30–33 秒；失败带抖动退避，最多约 303 秒。Controller 以接收时间判断：小于 90 秒在线、90–299 秒延迟、300 秒起离线；从未心跳是独立状态。
- HTTP 401/403 以退出码 4 停止同步，systemd 不重启该退出。系统支持、协议兼容与在线状态分别显示。
- 只读探测独立的 `proxyforge-singbox.service` 和 `/opt/proxyforge-agent/bin/sing-box`；不接管用户已有实例。机器 ID 哈希仅作提示，每次注册有新实例 ID；观察到的 IP 可能是 NAT/代理地址。
- 角色和标签只是清单元数据。撤销/移除 Agent 不会停止远端已运行的服务。

```bash
sudo systemctl status proxyforge-agent --no-pager
sudo journalctl -u proxyforge-agent
```

Agent 日志不记录凭据、响应正文或 Controller URL。

## 任务与升级

在 **Agent 服务器 → 任务**创建 sing-box 状态查询、刷新结果或取消任务。每次心跳成功后最多领取一个任务；`run --once` 执行一次心跳和至多一个任务。取消会拒绝后续结果，不能强行中止已开始的只读探测。

每个目录只使用一份配置。运行时持有 `config.lock`，旁边的 `job-results.json` 保存最近 128 个结果，最多 256 KiB，以 0600 权限原子替换并 fsync。执行期间不要编辑或删除日志；损坏或身份不匹配会停止任务执行，需要本地排查。日志绑定 Controller、Agent 与实例身份，不保证跨机器恰好执行一次，见 [B2 协议](../docs/AGENT_B2.md)。

已有安装先升级并备份 Controller，再停止 Agent 和 runtime socket/helper，确认执行中的事务结束或已用原版本恢复。私密备份完整 Python 包、systemd units、`/etc/proxyforge-agent/` 和 `/var/lib/proxyforge-runtime/`。从同一已验证提交替换安装器文件清单中的全部模块、固定 release JSON、helper 和 units；保持 root 所有权、0644 模式及不可由 Agent 写入的父目录，保留凭据、实例 ID、事务和 receipt。实际升级组件后才写对应能力标记，启动后核对心跳与状态查询。没有自动原地升级命令，不能重跑首次安装器。完整流程见[发布验收与恢复](../docs/RELEASE_ACCEPTANCE.md)。

仅回滚 Agent 时先停服务并恢复整份旧包。B3 Controller 仍接受 B1/B2 清单；退回 B2 前私密归档 B3 任务日志，禁用可选 runtime socket/helper，并取消待执行 runtime 任务。保留凭据与 runtime 文件以便恢复。Controller 退回 B1 需要恢复迁移前数据库，不能手动降低 `schema_migrations`。

## 本地停止与卸载

先在 Controller 撤销/移除 Agent，再在对应主机执行：

```bash
sudo systemctl disable --now proxyforge-agent.service
sudo rm -- /etc/systemd/system/proxyforge-agent.service
sudo systemctl daemon-reload
```

保留包和凭据目录供检查。管理员核实路径、备份及无其他服务使用后，才可自行清理 `/opt/proxyforge-agent`、`/etc/proxyforge-agent` 和专用用户。上述步骤不卸载 sing-box、不改变防火墙；可选 helper/runtime 的停用与恢复按 B3 流程单独处理。没有远程卸载动作。

## 开发调试

在仓库根目录以普通用户选择临时配置路径：

```bash
python3 -m agent.main --config /tmp/pf-agent/config.json register \
  --server http://127.0.0.1:8000 --allow-insecure --token-stdin
python3 -m agent.main --config /tmp/pf-agent/config.json run --once
```

token 从 stdin 输入。HTTP 仅允许显式开发选项；HTTPS 始终校验证书，跨域、同域和降级重定向均拒绝。生产使用可信 HTTPS 根地址。
