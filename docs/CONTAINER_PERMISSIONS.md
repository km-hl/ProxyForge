# Controller 非 root 容器与数据迁移

Controller 镜像和 Compose 均固定使用 **UID/GID 10001:10001**，仍监听 8000，持久化目录仍为 `/app/data`。程序文件由 root 所有；服务账号只需写入数据目录。Compose 移除全部 Linux capabilities 并开启 `no-new-privileges`。这不会赋予 Controller Agent/helper 权限，也不改变 API、schema 5 或 Agent 协议。

入口先检查身份及数据目录，再以 `exec` 启动 Uvicorn，保留正常信号处理。数据目录及子目录要求 0700、文件要求 0600，所有者为 10001:10001；服务使用 umask 077 创建新文件。身份不符、所有权不符、只读挂载、权限过宽或链接文件会使启动失败，并指向本文。入口不自动 chown，也不以 root 兜底。

以下命令适用于 **Linux Docker Engine、本地 POSIX 文件系统、默认 UID 映射**。Docker Desktop 的 Windows/macOS 共享目录、NFS/CIFS、rootless/userns-remap、额外 ACL 和 SELinux 策略需要单独验证；不能用放宽权限或禁用启动检查代替验证。UID 10001 的宿主机其他进程也可能读写这些数据，应避免账号冲突。

## 新安装

先完成 `.env` 准备，在实际仓库的物理路径执行。示例 `/srv/ProxyForge` 必须替换为自己的路径；本节只适用于 **尚无 data** 的安装。已有数据请使用下一节。

```bash
set -euo pipefail
cd -P /srv/ProxyForge
test ! -e ./data && test ! -L ./data
mkdir -m 0700 ./data
docker compose build --pull proxyforge
docker compose run --rm --no-deps --user 0:0 --entrypoint python \
  --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  proxyforge scripts/container_data.py --apply
docker compose up -d proxyforge
docker compose exec proxyforge id
```

最后应显示 UID/GID 10001。迁移命令是显式的一次性 root 工具，临时加入所有权/权限处理所需能力，不发布服务端口；运行完即删除，不改变正常服务身份。其语法依据 [Compose run 文档](https://docs.docker.com/reference/cli/docker/compose/run/)。Compose 使用 `create_host_path: false`，避免漏准备目录时自动创建 root-owned 挂载。

## 已有 root-owned 数据升级

1. 按[发布验收与恢复流程](RELEASE_ACCEPTANCE.md)记录旧提交、镜像、Compose/覆盖文件和 `.env`，停止所有 Controller 写入者，备份整个 `data/`（含 SQLite/WAL/SHM、部署密钥、模板历史及缓存），核验备份可读取。备份放在数据目录之外。必须先保存旧配置，再切换新提交。
2. 进入实际仓库物理路径，核对挂载源。不得将 `/`、家目录、其他服务目录或符号链接作为 `data`；不允许数据目录内另挂其他文件系统。下面命令不会替代对实际 Compose 覆盖文件的检查。

   ```bash
   set -euo pipefail
   cd -P /srv/ProxyForge
   test -d ./data && test ! -L ./data
   readlink -f ./data
   docker compose config --quiet
   docker compose stop proxyforge
   docker compose build --pull proxyforge
   ```

3. 先执行只读检查，确认可迁移。该工具固定操作容器内 `/app/data`，不接受任意路径或任意 UID 参数：

   ```bash
   docker compose run --rm --no-deps --user 0:0 --entrypoint python \
     --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
     proxyforge scripts/container_data.py
   ```

4. 确认所有写入者已停机、备份已完成后执行迁移，再启动：

   ```bash
   docker compose run --rm --no-deps --user 0:0 --entrypoint python \
     --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
     proxyforge scripts/container_data.py --apply
   docker compose up -d proxyforge
   docker compose exec proxyforge id
   ```

工具先检查整棵目录树，再将所有权改为 10001:10001，目录权限收紧为 0700、普通文件为 0600；不修改文件内容。旧有 0600 私有文件保持私有，旧有组/其他用户读权限会被移除。原本缺少所有者读写权限的文件或缺少遍历权限的目录会被拒绝，需人工确认其只读意图，工具不会自行放宽。

遍历与修改使用目录描述符和 `O_NOFOLLOW`，拒绝符号链接（包括目录链接）、硬链接、设备/FIFO/套接字以及跨文件系统节点；不要让并发进程移动目录或创建链接。该操作不是事务：磁盘/权限错误或中断仍可能使部分文件已迁移。修复原因后可在停机状态重复运行，或者恢复配套冷备份。检查失败时不要直接运行无范围的 `chown -R`，更不要使用 777。

## 验收与故障恢复

启动后检查管理登录、原订阅、节点、模板保存/历史、Agent 清单及撤销状态。检查日志中没有数据权限错误，重启后凭据和历史保持不变。首次管理密钥仍通过以下命令在本机读取，勿粘贴到工单或日志：

```bash
docker compose exec proxyforge cat /app/data/admin_token.txt
```

如失败，先停止新服务，保存故障现场。恢复旧镜像时也恢复旧 Compose/覆盖文件（其中可能没有固定 user）及一致的数据冷备份；不要只把新服务改为 root 强行启动。只改变所有权不改变数据格式，但升级后新增业务写入仍需单独决定恢复点，不能假设恢复旧备份无数据损失。

本地/CI 演练命令（Linux Docker 引擎）：

```bash
python scripts/check_controller_image.py docker
```

演练仅使用随机临时卷与临时 bind 目录，不挂载业务 data 或 `.env`，容器关闭外网且不发布端口。覆盖旧 root-owned 副本启动拒绝、迁移及重启、只读挂载拒绝、空 bind 首启、UID/GID/进程 capabilities、凭据、模板/历史、SQLite/WAL、部署密钥、机场缓存、链接迁移失败及旧镜像回退。单元测试另覆盖链接/FIFO/只读文件拒绝和迁移前预检查；实际生产副本及未列平台仍需发布验收。
