# Python 运行时与升级验证

Controller 的生产基线为 **Python 3.12 / Debian Bookworm**，Docker 基础镜像使用 `python:3.12.15-slim-bookworm` 并固定多架构 digest（见 Dockerfile）。Controller 完整 CI 在 Python **3.12、3.13** 上运行；其他版本暂不列入支持矩阵。Python 3.9 已结束上游支持，3.12 的上游安全支持持续到 2028 年 10 月，见 [PEP 596](https://peps.python.org/pep-0596/) 和 [PEP 693](https://peps.python.org/pep-0693/)。镜像标签见 [Docker 官方 Python 镜像](https://hub.docker.com/_/python)。

## Controller 与 Agent 分开管理

| 组件 | 支持与验证范围 |
| --- | --- |
| Controller 镜像 | Python 3.12、Bookworm；CI 在 Linux amd64 实际构建、启动和恢复 |
| Controller 源码 | Python 3.12 / 3.13 完整 Python 与 Node 回归；Mihomo 与 sing-box/systemd 任务使用 3.12 |
| Agent | 安装器继续接受 Python 3.9+，使用系统 Python 和标准库；独立 CI 在 3.9–3.13 运行 CLI、编译及 runtime engine 测试 |
| Agent 安装平台 | 仍为 Debian 12/13、Ubuntu 22.04/24.04，amd64/arm64；解释器 CI 不等于全部 OS × 架构安装验收 |

这次升级不改变 HTTP API、Agent/helper 协议、数据库 schema 5 或数据目录格式，也不要求升级已安装 Agent/helper。Python 3.9 的 Agent 检查用于保留代码兼容下限；生产 Agent 应使用目标发行版仍维护的系统 Python。Controller 3.13 的源码测试不表示已验证对应生产镜像。

## 升级和回滚

1. 按[发布验收与恢复流程](RELEASE_ACCEPTANCE.md)保存旧镜像的实际 ID/归档、代码版本、`.env` 和完整 `data/` 冷备份。停止写入后再备份 SQLite；数据库与 `deployment.key` 必须配套保存。
2. Docker 部署在选定已审查提交后执行：

   ```bash
   docker compose build --pull proxyforge
   docker compose up -d proxyforge
   docker compose exec proxyforge python --version
   docker compose exec proxyforge python -m pip check
   ```

3. 验证管理登录、现有订阅、模板历史、Agent 清单和撤销状态。镜像升级不删除 `data/config.json`，也不重新生成部署密钥。
4. 源码部署需用 `python3.12 -m venv .local/venv-312` 新建环境，再执行 `.local/venv-312/bin/python -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements.txt`；不要复用旧解释器创建的 `.venv`。开发环境改为安装 `requirements-dev.txt`。切换服务使用的解释器后重启并执行相同验收。
5. 回滚时先停止新服务，保存故障现场，再恢复已保留的旧镜像及其配套完整冷备份。若升级后发生新写入，恢复旧备份会丢失这些写入，应先确认恢复点。本次同 schema 的解释器回退测试不能代替未来跨 schema 的迁移评估。

## 隔离镜像演练

在有 Docker 引擎的开发机或一次性 CI runner 执行：

```bash
python scripts/check_controller_image.py docker
```

脚本构建真实 Dockerfile，以及使用独立旧版依赖锁的 Python 3.9 同代码 Bookworm 对照镜像；两者基础镜像均固定补丁版本和 digest。生成带随机名称的临时 Docker volume，写入合成模板、历史、自建节点、schema 5 数据库、有效/已撤销 Agent 凭据和加密校验样本；不挂载宿主机 `data/` 或 `.env`。`seed`、`check` 是容器内部阶段，不应对业务数据目录单独调用。

演练用镜像默认启动命令运行 Uvicorn：先在 3.9 上启动，停机冷复制完整卷，再在 3.12 上恢复并重启，最后在同一数据副本上回退至 3.9。检查 Web UI、未授权管理请求、管理 API、订阅节点、历史/配置文件指纹、SQLite 完整性及外键、凭据撤销和密钥解密。所有运行容器使用 `--network none`，不发布端口；构建仍需联网下载基础镜像与依赖。结束后清理本次随机命名的容器、卷和镜像，不执行全局 prune。

该演练是**同代码、同 schema 的解释器升级验证**，不是历史生产镜像回放；完整 Python 测试中的 `test_release_recovery.py` 另行覆盖部署数据、在途任务恢复、WAL 在线备份及密钥缺失/错误。实际 VPS 数据恢复、arm64 容器与真实公网节点链路仍需按发布流程验收。

生产/开发/旧版对照依赖、生成器和基础镜像 digest 已锁定，维护与验证命令见[依赖锁说明](DEPENDENCIES.md)。依赖版本可重复不等于镜像逐字节可复现；非 root 镜像迁移随后单独处理。
