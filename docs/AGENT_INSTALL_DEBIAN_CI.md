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

四组合首次完整成功记录：PR #48 的 `7961f711609f6c6ccca2a25fdf56159a7a94cc1d`，PR workflow `37780642839` 四项 VM job 均成功；Debian 12 内核为 `6.1.0-53` 的对应架构，Debian 13 内核以日志实际值为准。该轮使用同架构 TCG，保留真实平台、系统 Python、安装、HTTPS 心跳和 helper 生命周期日志。同期 push 的 Debian 12 arm64 在 cloud-init 初始 SSH 重置时失败，其余三项成功；后续修复只读等待的有界重试并添加回归，最新提交完整 CI 须再次核对。本记录不将单次成功当作所有云厂商或公网验收。

最终 `bee202986ca3d7a6cbd5b02dcbc2914409022e6f` 的 push `37783408093` / PR `37783416308` 均成功，52 项检查全部 SUCCESS；四 VM × 两轮全部通过。#48 已审查合并为 `c5946a293e05d7b7dc08578e557ccef1221825c9`。

## 真实公网 HTTPS operator 验收

`scripts/check_agent_public.py` 是独立的已授权运维入口，**不是前述 CI 脚本的生产开关**。仅用于控制面初次验收：现有 Agent、jobs、deployments、chains 必须均为空，否则停止。管理员先确认目标 Controller、业务范围和可用资源；在可信、root 控制的源码目录运行。不要将 CI 的 `GITHUB_ACTIONS` 标记伪造到生产环境。

宿主机要求 Linux amd64、root、可访问的 KVM、Docker bind-mounted `/app/data`、至少 2 GiB 可用内存和 3 GiB 空闲磁盘。需要 QEMU、qemu-img、cloud-localds、SSH，可按已确认的软件包变更范围准备：

```bash
sudo apt-get install --no-install-recommends --no-upgrade qemu-system-x86 qemu-utils cloud-image-utils openssh-client
```

先独立核对 `docker inspect` 的 Controller 镜像 ID 和安装来源；下列摘要占位符必须替换为已核验的完整值。`--expected-source-commit` 只能选驱动内已审查的两个来源：当前 `da2550a923f3a64a7d1e932a56090a34966f6ab7`，或历史 `977b16b41e0d5332d933df007e7a683189c1fdc8`。API 返回的 bootstrap/hash/完整命令必须与对应可信锚点逐字一致，不能由 API 自行选择任意 root 执行代码。

```bash
sudo python3 scripts/check_agent_public.py --disposable-vm \
  --controller-url https://your-controller.example \
  --expected-controller-image 'sha256:<已核验的64位镜像摘要>' \
  --expected-source-commit da2550a923f3a64a7d1e932a56090a34966f6ab7 \
  --output-dir /root/proxyforge-public-acceptance-YYYYMMDD-unique
```

输出目录必须全新、位于 Controller data 之外；其父目录及祖先必须由 root 持有、不可被 group/world 写入且无符号链接。写入注册记录前，驱动复制完整 data 的静态文件及目录权限，由 Controller 容器内与数据库 UID/GID 一致的运行用户使用 SQLite 在线 backup API 获取一致数据库，不复制热 WAL/SHM；保存原始 UID/GID/mode、SHA256 清单及私有 tar，逐项读取归档并在数据库副本核对 schema 5、integrity 和 foreign keys。配置在备份期间变化则停止。这是在线一致备份和副本读取演练，不替代涉及升级/迁移时的停写冷备；不会将备份恢复到生产数据库。线上 SQLite 的备份及资源数量检查只在 Controller 容器内执行；宿主机 root 不连接热数据库，使热 SQLite/WAL/SHM 访问维持在应用的数据用户与容器命名空间中。容器 User 必须与数据文件的数值 UID:GID 匹配，否则在数据库连接前拒绝。

随后启动自己的 Debian 12 amd64 KVM VM，固定云镜像与 SHA512 沿用前节。限定 1 CPU/1 GiB 内存，SSH 仅绑定宿主机回环地址，临时密钥、seed、overlay 在 0700 目录中，没有宿主机共享目录或公网入站端口。核对随机标记、独立 Debian 内核、真实发行版、systemd 和架构后，才向该 VM 传递安装命令。宿主机不安装 Agent，不替换现有 Controller 镜像或重启业务容器。

使用实际管理接口返回的普通安装命令和真实公网 HTTPS 根地址；不改 DNS/hosts，不添加测试 CA，不关闭证书校验。注册凭据只经私有管道进入 VM 的非回显 TTY，不进入参数、URL、环境、终端输出或 history。管理会话在 Controller 容器内生成并使用，管理 HTTP 禁止重定向；不会导出 session secret/cookie。检查 Agent 0600 身份、普通安装默认无 helper、重复安装拒绝及真实在线平台心跳后，才显式执行同一接口的 helper 命令。

任务通过真实 `POST /api/agents/{id}/jobs` 下发，由实际 Agent 守护进程经公网领取、持有租约、开始和回传结果，不由探针直接调用 runtime socket 代替。先查未安装状态，再测试固定 sing-box install/restart/rollback/stop/start；核对单次尝试、时间戳、重复 request_id 的幂等、专用非 root runtime 用户、默认无入站和身份不变。仅在运行期间真正看到 `lease_until` 增长时，报告 `lease_renewal_observed=true`；短任务通过不能当作续租或故障重领验收。

最后停止本次 runtime、撤销本次 Agent，等待其因凭据被拒绝以退出码 4 停止同步。正常结束、异常或 SIGTERM 会尽力先终止自己 QEMU，再仅删除随机名称、实例 ID 和未分配角色均匹配的临时 Agent 及其级联 jobs；配置文件、业务资源数量与所有运行容器的 ID/image/StartedAt/RestartCount 再次比较。保留正常注册凭据消费记录与审计事件；不回滚整份生产数据库。断电、SIGKILL 或公共入口失联时可能需要管理员凭保留备份检查临时记录，禁止猜测删除其他 Agent。

私有输出目录保留 `backup/manifest.json`、`backup/SHA256SUMS`、`backup/data.tar`、读取过的 data 副本和脱敏 `report.json`；不得上传备份、原始 API 响应、VM seed/密钥/磁盘/日志。报告分别记录验收成功、清理不变量和每个任务是否实际观察到续租；退出码非零不能当作验收通过。

该拓扑是 **同物理宿主机上的隔离 VM，经真实公网域名/HTTPS 入口访问 Controller**。它覆盖实际公网注册、心跳和队列结果回传，不能称为两个独立服务器/网络，也不验证所有平台、裸机、生产 Agent 升级、Reality/SS2022 公网代理握手或租约超时后的故障重领。生产 Controller 的旧固定来源验收与 master 的新来源 CI 需分别记录，不能据此声称新 helper unit 已部署。
