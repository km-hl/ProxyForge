# Debian 安装 CI 验收

本任务验证 Debian 12/13 × amd64/arm64 的普通 Agent 安装。每项运行在相同架构的独立 GitHub Ubuntu VM 上，启动官方 Debian 用户空间和 systemd PID 1 的一次性容器；不使用 QEMU 或更改平台声明。容器共享宿主机内核，**不能将结果称为完整 Debian VM、裸机或公网验收**。

## 固定来源和执行边界

- Debian 12：`debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587`。
- Debian 13：`debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f`。

这是官方多架构索引的固定 digest；来源于 [Docker 官方 Debian 镜像](https://hub.docker.com/_/debian)及[官方镜像元信息](https://github.com/docker-library/repo-info/tree/master/repos/debian/remote)，核对于 2026-10-08。镜像增加 systemd、系统 Python/venv、CA 和 sudo；测试 Controller 的依赖沿用项目哈希锁。发行版包从对应官方 apt 源安装，不宣称整个测试镜像可逐字节复现。

`tests/containers/debian-install.Dockerfile` 只复制已受 `.dockerignore` 隐私边界保护的源码，不带入 `.env`、data、MEMORY 或本地文件。`scripts/check_debian_installation.py` 必须显式使用 `--disposable-system-test`，且要求 GitHub CI、root 和匹配的真实宿主机架构；镜像架构还会再次核验，之后才启动容器。

需要 privileged 以启动真实 systemd；只允许在专用、可丢弃的 CI VM 运行。容器使用私有 cgroup namespace，不挂载宿主机目录、Docker socket 或 cgroup 目录，不发布端口。使用随机名称，仅清理自己创建的容器；成功或失败都会清理。不要在开发机、生产服务器或已有 Agent 主机执行。

## 实际验证

四项使用同一 `scripts/check_agent_installation.py`：`--expected-debian <12或13>` 与 `--expected-ubuntu` 互斥。写入前核对真实发行版、版本、架构和 `/usr/bin/python3`（Debian 12 为 3.11，13 为 3.13），收到心跳后再次核对 Agent 上报的平台、版本和 supported。

执行管理 API 返回的控制台命令，真实下载固定 bootstrap/source、隐藏 TTY 输入、systemd 服务启动、可信 HTTPS 注册与心跳。继续检查凭据 0600、默认不安装 helper、已有安装拒绝、注册凭据单次消费，以及凭据未进入输出、日志、进程参数快照或非交互 shell history。

HTTPS Controller 在容器回环地址运行，使用专用测试 CA 并保留证书/主机名校验；测试 Controller 的 venv 与 Agent 使用的系统解释器分开。测试不修改 Agent 0.6.0、固定 bootstrap/source/hash、API、schema 或生产镜像。

对应 CI 四项 job 全部成功后，可记为 **同架构 Debian 用户空间/systemd 容器安装实测**。目标提交结果仍须逐次核对。完整 Debian VM/裸机差异、真实公网 HTTPS、可选 helper 的全平台安装以及生产 Agent 升级继续单列验收，不能用容器结果代替。
