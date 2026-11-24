# ProxyForge Agent 运维与恢复（中文）

[English](README.md) · [Agent 安装指南](../docs/AGENT_INSTALL.md)

Agent 当前软件版本为 **0.6.0**，仅依赖系统 **Python 3.9+ 标准库**（无需任何第三方 Python 包）。它主动通过 HTTPS 连接 Controller 上报系统信息、发送心跳并执行白名单任务，自身不监听公网端口。

可选启用的本机 Unix Socket 特权辅助进程（`proxyforge-runtime.socket`）用于隔离管理 `sing-box`、`Caddy`、`go-gost`、`nftables` 多用户流量计数器及宿主机存量节点接管。

## 安装与升级

- **推荐方式（一键安装）**：在控制台 **「服务器与节点 → 添加服务器」** 生成 `/api/agent/install.sh` 一键命令执行，支持 `--runtime`、`--with-gost`、`--adopt-scan`、`--gh-proxy` 等选项（详见 [Agent 安装指南](../docs/AGENT_INSTALL.md)）。
- **源码目录安装**（已有受信任 checkout，须为 root 所有且非其他用户可写）：
  ```bash
  sudo bash agent/install.sh https://your-controller.example
  # 如需启用本机特权 runtime helper：
  sudo bash agent/install-runtime.sh
  ```
- **静默自动升级**：具备 `self_upgrade_protocol_version=1` 的 Agent 会在心跳中比对 Controller 的 `latest_bundle_sha256`，自动下载校验并通过特权 helper 原子替换代码、同步 systemd 单元及按需平滑重启。
- **存量旧 Agent 引导升级**：使用控制台一键脚本加 `--upgrade` 参数原地升级，保留既有 `/etc/proxyforge-agent/config.json` 与运行数据。

支持平台：**Debian 12/13**、**Ubuntu 22.04/24.04**（`amd64` / `arm64`）、`systemd`、Python 3.9+。安装凭据以 `0600` 写入 `/etc/proxyforge-agent/config.json`（目录 `0700`），服务以无特权用户 `proxyforge-agent` 运行；私有 CA 可在手动注册时传 `--ca-file /path/to/ca.pem`（持久化至 `/etc/proxyforge-agent/`）。

## 注册中断恢复

注册不会自动重试。若因网络中断导致控制台已生成记录但本地尚未落盘凭据：

1. 在控制台删除该未心跳的孤立记录，重新生成一次性注册 token（10 分钟有效）。
2. 在目标主机以服务用户补齐注册并启动：
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

## 运行排障

- 心跳间隔约 30–33 秒（失败指数退避，上限约 303 秒）；Controller 收到 `401/403`（凭据已撤销）时 Agent 以退出码 `4` 停止同步，systemd 不自动重启。
- 排查服务状态与日志（日志不含凭据或完整 Controller URL）：
  ```bash
  sudo systemctl status proxyforge-agent proxyforge-runtime.socket proxyforge-singbox --no-pager
  sudo journalctl -u proxyforge-agent -n 50 --no-pager
  sudo journalctl -u proxyforge-runtime -n 50 --no-pager
  ```
- 卸载停用（先在控制台撤销/移除服务器）：
  ```bash
  sudo systemctl disable --now proxyforge-agent.service proxyforge-runtime.socket \
    proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service 2>/dev/null || true
  ```
  确认备份无误后，再按需手动清理 `/etc/systemd/system/proxyforge-*.service`、`/etc/systemd/system/proxyforge-runtime.socket`、`/opt/proxyforge-agent`、`/etc/proxyforge-agent` 与 `/var/lib/proxyforge-runtime`。

## 本地开发调试

```bash
python3 -S -m agent.main --help
python3 -S -m unittest discover -s tests -p test_runtime_engine.py -v
python3 -S -m unittest discover -s tests -p test_nft_users.py -v
python3 -S -m unittest discover -s tests -p test_agent_self_upgrade.py -v
```
