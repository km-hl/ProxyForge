# Debian 安装 CI 验收

容器任务验证 Debian 12/13 × amd64/arm64 的普通 Agent 安装及随后显式启用的 helper。每项运行在相同架构的独立 GitHub Ubuntu VM 上，启动官方 Debian 用户空间和 systemd PID 1 的一次性容器；不使用 QEMU 或更改平台声明。容器共享宿主机内核，**不能将结果称为完整 Debian VM、裸机或公网验收**。

## 固定来源和执行边界

- Debian 12：`debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587`。
- Debian 13：`debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f`。

这是官方多架构索引的固定 digest；来源于 [Docker 官方 Debian 镜像](https://hub.docker.com/_/debian)及[官方镜像元信息](https://github.com/docker-library/repo-info/tree/master/repos/debian/remote)，核对于 2026-10-08。镜像增加 systemd、系统 Python/venv、CA 和 sudo；测试 Controller 的依赖沿用项目哈希锁。发行版包从对应官方 apt 源安装，不宣称整个测试镜像可逐字节复现。

`tests/containers/debian-install.Dockerfile` 只复制已受 `.dockerignore` 隐私边界保护的源码，不带入 `.env`、data、MEMORY 或本地文件。`scripts/check_debian_installation.py` 必须显式使用 `--disposable-system-test`，且要求 GitHub CI、root 和匹配的真实宿主机架构；镜像架构还会再次核验，之后才启动容器。

需要 privileged 以启动真实 systemd；只允许在专用、可丢弃的 CI VM 运行。容器使用私有 cgroup namespace，不挂载宿主机目录、Docker socket 或 cgroup 目录，不发布端口。使用随机名称，仅清理自己创建的容器；成功或失败都会清理。不要在开发机、生产服务器或已有 Agent 主机执行。

## 实际验证

四项使用同一 `scripts/check_agent_installation.py`：`--expected-debian <12或13>` 与 `--expected-ubuntu` 互斥。写入前核对真实发行版、版本、架构和 `/usr/bin/python3`（Debian 12 为 3.11，13 为 3.13），收到心跳后再次核对 Agent 上报的平台、版本和 supported。

执行管理 API 返回的控制台命令，真实下载固定 bootstrap/source、隐藏 TTY 输入、systemd 服务启动、可信 HTTPS 注册与心跳。继续检查凭据 0600、默认不安装 helper、已有安装拒绝、注册凭据单次消费，以及凭据未进入输出、日志、进程参数快照或非交互 shell history。

HTTPS Controller 在容器回环地址运行，使用专用测试 CA 并保留证书/主机名校验；测试 Controller 的 venv 与 Agent 使用的系统解释器分开。Agent 0.6.0 的 Python 模块与协议保持兼容；本次推进 bootstrap/source/hash 固定锚点以包含 helper unit 降权修复，API 结构、schema 与生产镜像运行状态不变。

对应 CI 四项 job 全部成功后，可记为 **同架构 Debian 用户空间/systemd 容器安装实测**。目标提交结果仍须逐次核对。完整 Debian VM/裸机差异、真实公网 HTTPS、生产 Agent 升级继续单列验收，不能用容器结果代替。


## helper 阶段

驱动传入 `--check-helper` 后，容器内的同一安装脚本继续执行控制台返回的固定 helper 命令，并以真实 Agent UID 经 Unix socket 验证对应架构 sing-box 的安装、重启、回滚、停止、启动与能力心跳。未经授权的本机 UID、socket 权限、独立服务用户、默认无入站监听与重复安装拒绝也列入检查，详见[完整验收边界](AGENT_INSTALL.md#显式-helper-安装验收)。完整 Debian 内核/VM、公网握手和 Controller 队列/租约仍不能由此替代。容器内执行预算为 900 秒、外层 job 为 20 分钟；下载失败或动作失败使对应 job 失败。

## 完整 Debian VM 验收

另外四项 `Agent + helper / Debian <版本> <架构> / full VM` 在同架构 GitHub Ubuntu 24.04 runner 内启动 QEMU。guest 启动自己的 Debian 内核和 systemd PID 1，使用 Debian 系统 Python 3.11/3.13；不共享宿主机内核、不跨架构模拟。宿主机可访问 `/dev/kvm` 时使用 KVM，否则使用同架构 TCG，并在日志注明；这仍是完整虚拟机，不代表裸机或全部云厂商环境。

`scripts/check_debian_vm_installation.py` 固定 [Debian 12 官方云镜像](https://cloud.debian.org/images/cloud/bookworm/20261006-2623/)（构建 `20261006-2623`）和 [Debian 13 官方云镜像](https://cloud.debian.org/images/cloud/trixie/20261001-2618/)（构建 `20261001-2618`）。四份 generic qcow2 的 SHA512 于 2026-10-08 从对应日期的官方 `SHA512SUMS` 独立核对并写入驱动；不从浮动 latest 或下载时取得的新 hash 决定信任。校验失败删除本次临时下载且不启动 VM，下载有 2 GiB 上限、30 秒读取操作超时及阶段间 600 秒预算检查；不承诺底层 DNS 的严格墙钟限制。

驱动只允许显式 `--disposable-system-test`、GitHub Linux runner 和匹配的真实宿主机架构。它先执行仓库隐私检查，再用 `git archive HEAD` 导出受控源码；忽略文件、MEMORY、本机配置和 data 不进入 guest。VM 的 qcow2 overlay、NoCloud seed、临时客户端与主机 SSH 密钥在 0700 临时目录中创建。SSH 使用固定临时主机公钥和 `StrictHostKeyChecking=yes`，QEMU 只转发 `127.0.0.1` 的随机 SSH 端口；没有宿主机目录共享、生产端口或外网入站。依据见 [cloud-init QEMU/NoCloud 指南](https://docs.cloud-init.io/en/latest/howto/launch_qemu.html)、[SSH 主机密钥配置](https://docs.cloud-init.io/en/latest/reference/modules.html#ssh)和 [QEMU 参数文档](https://www.qemu.org/docs/master/system/invocation.html)。

cloud-init 完成后，驱动核对本次随机 VM 标记、发行版/版本、架构、systemd PID 1、虚拟化类型和独立 Debian 内核，之后才安装测试 venv 和执行安装流程。apt 从该发行版官方源安装测试依赖，Python 包强制项目哈希锁；不宣称所有 apt 输入或 VM 磁盘可逐字节复现。

仅在专用、可丢弃的 CI runner 使用以下入口，**不要在开发机或生产服务器执行**：

```bash
python3 scripts/check_debian_vm_installation.py --disposable-system-test --expected-debian 12 --expected-arch amd64
```

CI 为四组合分别安装对应架构 QEMU、qemu-utils、cloud-image-utils 和 openssh-client；入口始终启用 `--check-helper`。guest 复用前述真实控制台命令、固定远端下载、隐藏 TTY 注册、可信回环 HTTPS、普通 Agent 默认无 helper、0600 凭据/重复安装拒绝，然后显式启用 helper，验收本机授权、实际 sing-box 生命周期与能力心跳。

每个步骤有超时，SSH 就绪最多 480 秒，cloud-init/SSH 稳定等待 180 秒（只读等待允许重试连接重置，真实 cloud-init 错误立即失败），测试依赖准备 600 秒，安装/helper 900 秒，job 总预算 40 分钟。正常退出或异常时仅终止自己启动的 QEMU，等待退出后清理临时密钥、seed 和磁盘；强制取消由一次性 runner 销毁兜底。seed、私钥、磁盘和 guest 日志不上传为 artifact。

新增任务的实际结果须按目标提交四项 job 核对；任务存在不等于验收成功。完整 VM 通过后，真实公网 HTTPS、Controller 队列/租约、各平台公网代理握手、裸机差异和生产升级仍分别待验收。
