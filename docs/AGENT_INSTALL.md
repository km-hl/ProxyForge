# Agent 完整下载安装命令

这份指南提供开发计划第 16 项第一阶段的完整入口：固定 bootstrap → 校验其 SHA256 → 下载固定官方源码归档 → 校验归档 → 在 root 控制的目录中准备 Agent → 执行首次安装。控制台复制按钮和真实空白主机安装矩阵仍是下一阶段。

命令入口体验参考 [Komari 官方快速安装](https://www.komari.wiki/install/quick-start)，凭据继续采用 ProxyForge 的隐藏 TTY 输入。没有采用将注册 token 放入参数的方式。

## 版本与前提

- Agent 软件版本 **0.6.0**，固定来源为已合并 #39 的完整提交 `977b16b41e0d5332d933df007e7a683189c1fdc8`；不是 `master` 或 `latest`。
- 官方源码地址：`https://codeload.github.com/km-hl/ProxyForge/tar.gz/977b16b41e0d5332d933df007e7a683189c1fdc8`。
- 源码归档 SHA256：`408460fa77682ea8fed5eb3591cf7f737f38072970d91c2ea006238029805361`。已下载并逐一比对其中 24 个 Agent 文件与该提交 Git blob 一致。
- bootstrap 自身使用下列命令中的另一固定提交与 SHA256。请从经过审查的可信仓库版本取得本页；命令内的 hash 是预期值，不能改成下载后现场计算的值。源归档若被 GitHub 重新打包导致 hash 变化，将停止，需要维护者重新核验，不自动接受新包。
- 目标是 Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64，已运行 systemd、系统 Python 3.9+、系统 CA、可用的 `sudo` 和交互终端。若系统缺少 Python/CA，可先由管理员执行 `sudo apt-get update && sudo apt-get install --no-install-recommends python3 ca-certificates`。
- 使用已升级 Controller 的可信公网 HTTPS 根地址；域名须为 ASCII 完整域名（国际化域名用 punycode），或公网 IP，允许显式端口。不要附加路径、凭据、query 或 fragment。域名的 DNS 与对外可达性需自行确认；安装器不会把一次地址格式检查当作公网验收。
- 目标主机需能直连 `raw.githubusercontent.com` 和 `codeload.github.com`。下载不读取代理环境变量、不跟随重定向、保持系统 CA/TLS 验证。私有 CA Controller 使用[原手动注册流程](../agent/README.zh-CN.md)，不要关闭 TLS 验证。

当前使用现有官方源码归档，未发布新的二进制/最小包 Release，也未选择正式版本 tag 或许可证。维护者的最小包构建与 manifest 契约见[安装产物说明](AGENT_ARTIFACTS.md)。

## 1. 普通 Agent 首次安装

仅将第一行的 `https://your-controller.example` 替换为真实 Controller 根地址，然后在目标 Linux 的 Bash 终端复制整个代码块执行。无需先找到源码目录，也无需在目标安装 Git。不要把注册 token 放进命令。

```bash
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 /usr/bin/python3 -I - install --server https://your-controller.example <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/3fb7d7ad626ab528929e8c70ee954fdca0d8d01a/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "fd5ca574078f721746dd3ddc864421113460b04f41cfc010bfca30177980afb8":
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

## 2. 可选：明确启用本机 root helper

先完成普通 Agent 安装，阅读 [B3 运行环境边界](AGENT_B3.md)。下列命令只适用于与上述固定源码完全一致的 Agent；已有其他版本先按升级流程处理，不自动替换旧 Agent。helper 属于独立的本机高权限操作，不传 Controller 地址或注册 token。

```bash
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 /usr/bin/python3 -I - runtime <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/3fb7d7ad626ab528929e8c70ee954fdca0d8d01a/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "fd5ca574078f721746dd3ddc864421113460b04f41cfc010bfca30177980afb8":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {"__name__": "__main__"})
PROXYFORGE_BOOTSTRAP
```

```bash
sudo systemctl status proxyforge-runtime.socket --no-pager
```

代码进入 helper 安装器前，逐一检查已安装 Agent 文件内容和目录所有权；不能只写能力标记冒充升级。后续 Reality、SS2022 和链路配置见 [Agent 中文说明](../agent/README.zh-CN.md)。

## 3. 仅下载校验（不需要 root）

以下命令验证真实固定下载地址、bootstrap hash、源码归档及 Agent 文件完整性；不创建安装目录、不注册、不启动服务。适合先检查下载链路，但不是安装验收。

```bash
/usr/bin/python3 -I - check <<'PROXYFORGE_BOOTSTRAP'
import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/3fb7d7ad626ab528929e8c70ee954fdca0d8d01a/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "fd5ca574078f721746dd3ddc864421113460b04f41cfc010bfca30177980afb8":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {"__name__": "__main__"})
PROXYFORGE_BOOTSTRAP
```

## 安全与失败处理

引导命令先在内存中校验 bootstrap，再执行同一份字节；使用 Python `-I`，安装命令清空继承环境。固定源码先校验完整 SHA256，再做有界解压与全归档路径/成员检查，只把明确列出的 Agent 普通文件写到新建 `/var/lib/proxyforge-agent-install-*` 私有目录。代码目录及父目录必须由 root 所有，不能有组/其他用户写权限、符号链接或不可信硬链接。不会从普通用户可替换的下载文件重新读取并作为 root 执行。

源码下载最多 8 MiB，展开最多 32 MiB，单成员最多 1 MiB；拒绝路径穿越、重复、链接、设备及未知 PAX 字段。下载连接/读取有 20 秒操作超时和阶段间 60 秒预算检查，不承诺 DNS/底层调用的严格 60 秒墙钟终止。失败停止；不自动重试注册。

首次安装发现已有 Agent 目录、unit（包括系统/vendor/generated unit）、用户或残留符号链接时拒绝覆盖。helper 发现已安装 runtime 或 Agent 版本不一致时拒绝继续。安装过程中也再次核对前置条件。临时源码目录会清理，已创建的 Agent 用户、配置、unit 与凭据不会在失败时被自动删除。

| 情况 | 处理 |
| --- | --- |
| 下载、TLS、重定向、hash 或归档校验失败 | 检查目标主机网络与可信文档版本；不跳过 hash、不改用 `curl \| bash`、不关闭证书校验 |
| 平台、systemd、root 目录权限或交互 TTY 不满足 | 使用支持的主机和交互终端；核对目录权限，不自动放宽检查 |
| 已有安装、用户或残留路径 | 按[恢复与升级指南](../agent/README.zh-CN.md)处理；不要直接重跑首次安装器或删除凭据 |
| token 过期/已使用、注册响应丢失或本地写入失败 | 核对 Controller 的孤立 Agent 记录，移除后生成新 token；按中文说明从已安装包手动完成注册 |
| helper 检测到 Agent 版本不同 | 先停止相关服务、私密备份、完整升级同一版本模块和 unit；不自动覆盖现有安装 |
| 本机服务成功但控制台未见心跳 | 分别检查可信 HTTPS 地址、证书、服务日志和 Controller 状态，不重复注册 |

升级、回滚、重装和卸载不是首次安装命令的隐含选项，详见[Agent 中文恢复指南](../agent/README.zh-CN.md)和[发布验收流程](RELEASE_ACCEPTANCE.md)。

## 验证记录与下一阶段

单元测试覆盖 hash 失败不执行、路径/链接/设备/大小限制、URL/命令注入、无 token 参数、环境隔离、已有路径拒绝、版本不一致及失败清理。CI 在 Python 3.9–3.13 执行，Ubuntu 24.04 的额外步骤下载真实固定归档，使用 disposable runner 的 root 权限测试目录/软硬链接/所有者检查；不在此测试中执行实际安装器。

Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64 的**特权首次安装与 HTTPS 注册/心跳矩阵仍待完成**；当前不把允许列表、模拟安装器或目录保护测试写成完整实测。后续控制台入口需配置可信 Controller HTTPS 地址，复用上述固定下载与 hash，完成 UI 复制命令的空白主机验收后再交付。

维护者可用 `python -m scripts.agent_install_command --bootstrap-commit <完整提交> --bootstrap-sha256 <可信SHA256> --server https://your-controller.example` 重新生成命令；可选 `--action runtime` 或 `--action check`，这两种操作不传 `--server`。修改 bootstrap 后须同步固定提交、hash 与文档，不能只改下载 URL。
