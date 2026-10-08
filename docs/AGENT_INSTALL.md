# Agent 完整下载安装命令

这份指南提供开发计划第 16 项的完整入口：固定 bootstrap → 校验其 SHA256 → 下载固定官方源码归档 → 校验归档 → 在 root 控制的目录中准备 Agent → 执行首次安装。控制台「添加服务器」提供相同的固定安装命令；平台实测范围见文末。

命令入口体验参考 [Komari 官方快速安装](https://www.komari.wiki/install/quick-start)，凭据继续采用 ProxyForge 的隐藏 TTY 输入。没有采用将注册 token 放入参数的方式。

安装参数、英文终端提示与中文处理建议见[安装命令帮助](AGENT_INSTALL_HELP.md)。

## 版本与前提

- Agent 软件版本 **0.6.0**，固定来源为包含 helper 降权修复的完整提交 `da2550a923f3a64a7d1e932a56090a34966f6ab7`；不是 `master` 或 `latest`。
- 官方源码地址：`https://codeload.github.com/km-hl/ProxyForge/tar.gz/da2550a923f3a64a7d1e932a56090a34966f6ab7`。
- 源码归档 SHA256：`3a95a0edac4ee87445feaffb10b053e6c4cee78e4b988dd5b1675768ac7b9a1c`。已下载并逐一比对其中 24 个 Agent 文件与该提交 Git blob 一致。
- bootstrap 自身使用下列命令中的另一固定提交与 SHA256。请从经过审查的可信仓库版本取得本页；命令内的 hash 是预期值，不能改成下载后现场计算的值。源归档若被 GitHub 重新打包导致 hash 变化，将停止，需要维护者重新核验，不自动接受新包。
- 目标是 Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64，已运行 systemd、系统 Python 3.9+、系统 CA、可用的 `sudo` 和交互终端。若系统缺少 Python/CA，可先由管理员执行 `sudo apt-get update && sudo apt-get install --no-install-recommends python3 ca-certificates`。
- 使用已升级 Controller 的可信公网 HTTPS 根地址；域名须为 ASCII 完整域名（国际化域名用 punycode），或公网 IP，允许显式端口。不要附加路径、凭据、query 或 fragment。域名的 DNS 与对外可达性需自行确认；安装器不会把一次地址格式检查当作公网验收。
- 目标主机需能直连 `raw.githubusercontent.com` 和 `codeload.github.com`。下载不读取代理环境变量、不跟随重定向、保持系统 CA/TLS 验证。私有 CA Controller 使用[原手动注册流程](../agent/README.zh-CN.md)，不要关闭 TLS 验证。

当前使用现有官方源码归档，未发布新的二进制/最小包 Release，也未选择正式版本 tag 或许可证。维护者的最小包构建与 manifest 契约见[安装产物说明](AGENT_ARTIFACTS.md)。

## 控制台复制入口

部署管理员在 `.env` 设置 `PROXYFORGE_PUBLIC_URL="https://your-controller.example"`，换成目标 Agent 可访问的真实 HTTPS 根地址。Compose 部署修改后执行 `docker compose up -d --force-recreate` 使环境生效；直接运行则在服务环境中配置并重启 Controller。不要填浏览器临时地址或含密钥的链接。

进入「服务器 → 添加服务器」，核对显示的 Controller、Agent 版本、固定提交和 SHA256，复制普通 Agent 安装命令到目标终端。等终端出现隐藏输入提示后，填写服务器名称并点击「生成注册凭据」，将一次性凭据粘贴到终端。完成后关闭窗口、刷新服务器列表，确认收到心跳并显示在线。安装命令不含凭据；关闭窗口、退出登录或会话失效会清除页面中的凭据，重新打开不会取回原凭据。

「只读下载校验」和「启用托管 runtime」位于可展开区域。后者是明确的可选 root 辅助服务操作，必须先完成普通 Agent 安装；复制或生成命令本身不会在远端执行任何操作。

缺少或错误的配置只显示配置说明及中文指南，不生成猜测地址的命令；仍保留手动安装的一次性凭据入口。剪贴板不可用时会选中命令，按系统复制快捷键手动复制。

管理接口 `GET /api/agents/install-command` 仅接受管理鉴权，返回 `available`；可用时包含 `controller_url`、`agent_version`、`source_commit`、`bootstrap_commit`、`bootstrap_sha256` 与 `commands.install/runtime/check`。不可用时只有固定的 `message`，不回显非法配置。接口不创建凭据、不下载或执行代码，不信任请求的 Host/转发头，并返回 `Cache-Control: no-store`。原注册接口及 10 分钟单次消费规则不变。

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
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/00d5a604499e5b22081bc280d4e1e3f0a69b650c/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "28fa9a875ef5c5513960cfbe8be269fe4a7bd688bb119a62bf461a3625df91c2":
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
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/00d5a604499e5b22081bc280d4e1e3f0a69b650c/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "28fa9a875ef5c5513960cfbe8be269fe4a7bd688bb119a62bf461a3625df91c2":
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
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/00d5a604499e5b22081bc280d4e1e3f0a69b650c/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "28fa9a875ef5c5513960cfbe8be269fe4a7bd688bb119a62bf461a3625df91c2":
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

独立 CI 任务 `Agent + helper / Ubuntu <版本> <架构> HTTPS` 覆盖 Ubuntu 22.04/24.04 × amd64/arm64 四种原生主机组合（[GitHub 官方运行器列表](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)），每项独立运行，失败不取消其他组合。任务运行 `scripts/check_agent_installation.py --disposable-system-test --expected-ubuntu <22.04或24.04> --expected-arch <amd64或arm64> --check-helper`：从真实管理 API 获取与 UI 相同的命令，下载固定远端代码，通过真实控制 TTY 隐藏输入注册凭据，启动 systemd 服务并等待 Controller 收到 HTTPS 心跳。检查 0600 凭据、服务用户、默认未启用 helper、重复安装不覆盖、凭据重复消费被拒绝，以及终端输出/服务日志/进程参数快照/非交互 shell history 未含凭据。浏览器复制、关闭/迟到响应、重复点击、剪贴板失败和登录失效另由前端行为测试覆盖。

| 平台 | amd64 | arm64 |
| --- | --- | --- |
| Ubuntu 24.04 | CI 安装与 HTTPS 心跳 | CI 安装与 HTTPS 心跳 |
| Ubuntu 22.04 | CI 安装与 HTTPS 心跳 | CI 安装与 HTTPS 心跳 |
| Debian 12 | 原生 systemd 容器 CI | 原生 systemd 容器 CI |
| Debian 13 | 原生 systemd 容器 CI | 原生 systemd 容器 CI |

每次安装前校验真实 `/etc/os-release`、机器架构和 `/usr/bin/python3`，与矩阵参数不符即失败且不修改主机。Ubuntu 的 Controller 测试进程使用 setup-python 的 3.12，Debian 的测试 venv 使用发行版 Python；Agent 安装器与服务仍使用系统 Python（Ubuntu 22.04 为 3.10，24.04 为 3.12），不能用 Controller Python 代替该兼容性验证。收到心跳后再核对 Agent 上报的 OS、版本、架构、软件版本和 supported 标志；实际平台和系统 Python 版本写入 CI 日志，不上传凭据或运行数据。

Debian 四项在同架构 GitHub VM 内运行官方 Debian 用户空间/systemd PID 1 的一次性容器，系统 Python 为 3.11/3.13；共享宿主机内核，不代表完整 Debian VM/裸机验收。固定镜像、参数、特权范围与验证见[Debian CI 说明](AGENT_INSTALL_DEBIAN_CI.md)。

表中 CI 项表示持续执行的测试入口，是否通过以目标提交八项 job 的结果为准。该 CI 使用隔离 runner 的测试域名、回环 HTTPS Controller 和专用测试 CA（保持证书/主机名校验），不是公网可达性验收；不在开发机或生产运行此特权脚本。CI 结果应随 PR/发布记录核对，不能把平台允许列表、进程快照或单元测试当作全部主机/整个安装期间的完整证明。真实公网 HTTPS、完整 Debian VM/裸机四组合、生产升级仍待分别验收。helper 安装 CI 的新结果也须按目标提交八项 job 核对，不代表公网链路已验收。GitHub 镜像预装了测试工具，不等同于所有云厂商的最小系统镜像。

维护者可用 `python -m scripts.agent_install_command --bootstrap-commit <完整提交> --bootstrap-sha256 <可信SHA256> --server https://your-controller.example` 重新生成命令；可选 `--action runtime` 或 `--action check`，这两种操作不传 `--server`。修改 bootstrap 后须同步固定提交、hash 与文档，不能只改下载 URL。

## 显式 helper 安装验收

八项安装 CI 均在普通 Agent 验收后显式传入 `--check-helper`，执行同一管理 API 返回的 `commands.runtime` 命令。先确认普通安装没有 helper，再核验 socket 为 root:proxyforge-agent、0660，普通 Agent 的配置/身份没有改变；启用 helper 本身不下载 sing-box。

随后使用已安装 Agent 模块和系统 Python，切换到真实 `proxyforge-agent` UID，通过 Unix socket 执行固定版本 sing-box 的安装、重启、回滚、停止与启动，实际下载对应架构二进制并运行 systemd 服务。核对 sing-box 进程属于专用非 root 用户、默认配置没有入站监听、重复 helper 安装被拒绝；等待 Controller 收到能力和运行状态心跳。额外用 root 调用同一 socket，确认不属于 Agent UID 的调用被拒绝且没有创建 runtime。

本测试覆盖显式安装、本机授权、真实进程和 HTTPS 能力心跳；生命周期动作由本机测试客户端发给 helper，**不代替 Controller 队列/租约的端到端验收**。普通安装仍默认不启用 helper，现有单架构 Reality/SS2022 链路 CI 单独保留；这八项不宣称完成各平台公网代理握手。脚本停止自己在本次测试中启用的服务，容器由外层驱动清理，Ubuntu VM 随 CI 销毁，不清理生产安装。

### systemd 降权检查修复与已安装 helper

八组合验收发现，systemd 255/257 的 seccomp 初始化可能移除未显式保留的 `CAP_SETUID`，使 root helper 无法将配置检查子进程切换到专用 runtime 用户。helper unit 显式设置 `AmbientCapabilities=CAP_SETUID`，保留已有设计要求的降权能力；`NoNewPrivileges=true`、目录保护、socket 调用方校验和非 root sing-box 服务保持有效。依据见[systemd 255 初始化源码](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c#L4484-L4490)。

普通 Agent 的 Python 模块、0.6.0 版本、身份凭据和协议均未改变。已安装旧 helper 的主机须由管理员先私密备份 Agent 配置、runtime 数据及旧 unit，停止 `proxyforge-runtime.socket` 与 `proxyforge-runtime.service`，核对新版固定来源中的 unit 后替换 `/etc/systemd/system/proxyforge-runtime.service`，执行 `sudo systemctl daemon-reload` 和 `sudo systemctl start proxyforge-runtime.socket`，再验证实际 runtime 操作与心跳；无需删除配置或重新注册。回退时停止 helper、恢复备份 unit 并重新加载/启动 socket。旧环境如果缺少该能力，恢复旧 unit 会恢复原安装失败限制。本 CI 不在生产主机执行升级。
