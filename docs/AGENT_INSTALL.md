# Agent 安装指南

支持 **Debian 12/13**、**Ubuntu 22.04/24.04**（`amd64` / `arm64`）、`systemd` 与系统 Python 3.9+。

## 方式一：一键安装（推荐，Komari 风格）

Controller 直接托管带精确 SHA256 校验的安装包 `/api/agent/package.tar.gz` 与安装脚本 `/api/agent/install.sh`。

1. 在 `.env` 中配置 `PROXYFORGE_PUBLIC_URL="https://your-controller.example"`（目标机器可访问的 HTTPS 根地址）并重启 Controller。
2. 打开控制台 **「服务器与节点 → 添加服务器」**，填写名称并勾选可选项，一键复制命令在目标 VPS 上执行：
   - `--runtime`：同时启用本机特权 `proxyforge-runtime.socket`（用于托管 `sing-box`、`Caddy`、`go-gost` 与 `nftables` 用户计费）。
   - `--with-singbox` / `--with-caddy` / `--with-gost` / `--with-all`：预装固定哈希校验的二进制。
   - `--adopt-scan`：安装上线后自动扫描宿主机既有 `sing-box` / `xray` 服务。
   - `--upgrade`：原地升级已有 Agent 代码与 systemd 单元（保留配置与凭据）。
   - `--reinstall`：清理后全新重装。
   - `--gh-proxy <mirror>`：为 GitHub 资产下载配置并持久化镜像前缀。
   - `-t <token>`：内联单次 10 分钟有效的 `pfreg_` 注册凭据（不传则在终端隐藏提示输入）。

上线后，具备自升级协议的 Agent 会在心跳中比对 `bundle_sha256` 自动拉取并静默平滑升级；升级恢复与卸载说明见 [Agent 中文说明](../agent/README.zh-CN.md)。

---

## 方式二：GitHub 固定 Commit 离线校验安装（保留兼容）

如需从固定 GitHub 提交经双层 SHA256 校验安装，可使用下列三条固定命令（不依赖 Controller 托管安装包；须能直连 `raw.githubusercontent.com` 与 `codeload.github.com`）。

- Agent 软件版本：`0.6.0`（纯 Python 3.9+ 标准库）
- 固定源码提交：`9738da476fbc3bf6702d335a9b7424192902add5`
- 许可说明见 [许可证与第三方归属](LICENSING.md)

### 1. 普通 Agent 首次安装

将第一行的 `https://your-controller.example` 替换为实际 Controller 根地址后执行，在隐藏提示处粘贴一次性注册凭据：

```bash
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 /usr/bin/python3 -I - install --server https://your-controller.example <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/500b025e48a8b4a7f01c53ebc640145bcad916db/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "dcbc31342fec1b372c6735e92613395b94cba089f83eab9c6b2fdd98631acd68":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {"__name__": "__main__"})
PROXYFORGE_BOOTSTRAP
```

脚本下载与校验完成后，在 **Agent 服务器 → 添加服务器**生成一次性凭据，再粘贴到隐藏提示。凭据有效期 10 分钟，只消费一次；不能放在 URL、命令参数、历史、日志或浏览器持久存储。默认仅安装普通 Agent，不启用 runtime helper，不修改防火墙。

```bash
sudo systemctl status proxyforge-agent.service --no-pager
sudo journalctl -u proxyforge-agent.service -n 30 --no-pager
```

随后在 Controller 检查最近心跳。服务启动成功不等于 Controller 已收到心跳，也不等于公网代理链路已验收。

### 2. 可选：启用本机 root helper

先完成普通 Agent 安装，再显式启用本机 Unix Socket 特权辅助进程：

```bash
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 /usr/bin/python3 -I - runtime <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/500b025e48a8b4a7f01c53ebc640145bcad916db/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "dcbc31342fec1b372c6735e92613395b94cba089f83eab9c6b2fdd98631acd68":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {"__name__": "__main__"})
PROXYFORGE_BOOTSTRAP
```

```bash
sudo systemctl status proxyforge-runtime.socket --no-pager
```

代码进入 helper 安装器前，逐一检查已安装 Agent 文件内容和目录所有权；不能只写能力标记冒充升级。后续 Reality、SS2022 和链路配置见 [Agent 中文说明](../agent/README.zh-CN.md)。

### 3. 仅下载校验（不需要 root）

只验证下载地址、bootstrap SHA256 与源码归档完整性，不写入安装目录、不注册、不启动服务：

```bash
/usr/bin/python3 -I - check <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/500b025e48a8b4a7f01c53ebc640145bcad916db/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "dcbc31342fec1b372c6735e92613395b94cba089f83eab9c6b2fdd98631acd68":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {"__name__": "__main__"})
PROXYFORGE_BOOTSTRAP
```

## 故障排查

| 情况 | 处理方式 |
| --- | --- |
| 下载、TLS 或 SHA256 校验失败 | 检查网络可达性，或在一键安装中通过 `--gh-proxy` 指定镜像；勿关闭证书或哈希校验 |
| 已有 Agent 安装 | 使用一键脚本 `--upgrade` 原地升级，或参考 [Agent 中文说明](../agent/README.zh-CN.md) 恢复 |
| 一次性凭据过期或注册中断 | 在控制台移除未心跳的孤立记录，重新生成 10 分钟有效的新 token |
| 服务已启动但控制台未见心跳 | 执行 `sudo journalctl -u proxyforge-agent -n 40 --no-pager` 检查连通性与证书 |
