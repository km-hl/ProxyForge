# Controller / Agent 发布验收与恢复

本轮功能交付覆盖 Template Revision、Agent 注册与任务、托管 sing-box、直连 Reality、SS2022 落地与链路、托管节点 UI。下一步是固定发布提交，演练数据恢复，再执行目标环境验收。CI 成功不等于生产已经升级，也不等于公网链路可用。

## 1. 修改文件与范围

`tests/test_release_recovery.py` 增加隔离数据演练；本文给出统一上线流程；README 与 Agent 操作说明链接到本流程。本阶段不新增远程动作、迁移、监听端口或自动发布功能。

## 2. 数据模型与备份集合

Controller 当前 schema 5；模板历史仍在文件中，不在 SQLite。完整恢复集合包括：

- 固定代码提交、旧容器镜像 ID、实际使用的 Compose 文件及覆盖文件、`.env`。
- 整个 `data/`，包括配置、手工节点、机场、缓存、模板、`history/`、事务恢复记录、`proxyforge.db` 及存在的 WAL/SHM。
- 与数据库配对的 `deployment.key`；没有部署记录时可以尚不存在。有部署记录时丢失密钥应停止发布和任务领取，不能生成新密钥冒充恢复。

停止所有 Controller 写入者后做完整冷备。不要只复制运行中的 `.db`；SQLite backup API 可生成数据库一致快照，但不能独自保证 YAML、密钥与数据库处于同一时刻。本轮在线 WAL 测试只证明数据库快照语义。

备份按凭据处理：目录 0700、文件仅管理员可读，不能上传 CI artifact、工单或公共存储。`MEMORY.md` 是本机工作记忆，始终 Git/Docker 忽略，不属于部署或备份集合。

## 3. API 验收

| 检查 | 预期 |
| --- | --- |
| 首页、登录、原订阅 URL | 页面可加载；原管理凭据和订阅凭据继续可用 |
| 未认证 `/api/config`、`/api/agents` | 401 |
| Agent / 订阅 token 访问管理 API | 401，不回显 token |
| `GET /api/template` | content 与 revision 匹配；未经编辑内容不变 |
| 模板两个会话竞争保存 | 第二个过期版本请求 409，草稿保留 |
| `GET /api/agents/managed/nodes` | 直连/链路、任务状态、归属正确；无部署秘密 |
| `GET /api/nodes` 与订阅 | 手工节点保留；仅符合发布条件的托管节点进入输出 |

用浏览器或从服务器进程内读取已保存凭据进行验收；不要把带 token 的 URL、请求头或配置原文打印到终端日志。不要在升级验收中随意更换管理/订阅 token。

## 4. 鉴权与恢复边界

恢复 `config.json` 保留原管理验证信息与订阅密钥；恢复数据库保留 Agent 凭据摘要及撤销状态。Agent 本地凭据不在 Controller 备份内：每台机器的 `/etc/proxyforge-agent/` 应单独私密备份。

旧快照也会恢复旧撤销状态和旧任务状态。因此灾难恢复后先隔离 Agent 通道并核对备份之后的撤销、部署和任务变更，再允许 Agent 同步。不能将“快照内部一致”理解为“与当前远端状态一致”。

## 5. Agent 版本与升级顺序

固定 Agent 安装产物、manifest 字段及预期 SHA256 的可信来源要求见[安装产物说明](AGENT_ARTIFACTS.md)。构建/校验通过不等于正式 Release 已发布，也不代替目标主机安装验收。

首次安装可用[完整下载、双层 SHA256 校验与安装命令](AGENT_INSTALL.md)，已有安装仍走以下升级/恢复流程。该引导命令固定 Agent 0.6.0 源码；不要因为 Controller 代码已更新就自动改动 Agent pin。

先升级 Controller，再按需要逐台升级 Agent。B6 沿用 Agent 0.6.0；旧 Agent 可以继续清单/已支持动作，新动作受各自 capability 门控。

已有机器不能重跑首次安装脚本。升级前停止 Agent 以及 runtime socket/helper，确认执行中的事务已结束或先用原版本恢复；私密备份已安装包、systemd units、`/etc/proxyforge-agent/`、`/var/lib/proxyforge-runtime/`。后者包含配置秘密、current/previous 和事务/receipt，不能只备份一个 JSON。

从同一固定提交更新完整 Agent 模块、release manifest、helper 和 units，保持 root 所有权及不可由 Agent 写入的父目录。完成实际组件升级后才写对应能力标记；不能单独创建标记来解锁操作。详见 [B3](AGENT_B3.md)、[B4](AGENT_B4.md)、[B5a](AGENT_B5_LANDING.md)、[B5b](AGENT_B5_CHAIN.md)。升级 Controller 本身不会安装 Agent 或打开代理端口。

## 6. 状态与远端验收

任务成功是 Controller 收到的结果；心跳在线、最近配置成功、当前运行状态、公网可达应分别验收。离线不证明代理已停止，撤销凭据也不停止远端监听。

在明确用于验收的入口/落地机器上依次检查：直连 TCP/UDP、经落地 TCP/UDP、两节点并存、落地不可用时链路不走直连、移除链路后原直连保留。破坏性场景应在隔离测试机器执行；已有业务服务器只执行约定范围内的操作。自行核对 NAT、防火墙、DNS、SNI 和客户端协议支持，系统不会重写现有防火墙。

## 7. Job 与恢复

Controller 快照恢复后，未完成任务的租约可能已经过期；仍在 deadline 内时会以相同 job ID、revision 和快照重新领取，新 lease 拒绝旧结果。超出 deadline 或重试次数则失败，需要核对远端后重新申请操作。

Agent 的 `job-results.json` 与 helper receipt 提供重放依据，必须保留。测试中的结果回报是模拟 Agent 成功响应，不能据此宣称恢复时远端动作恰好执行一次。跨机器快照恢复不是分布式回滚。

## 8. 自动化证据与未验收项

从仓库根目录运行：

```bash
python -m unittest discover -s tests -p test_release_recovery.py -v
python -m unittest discover -s tests -v
node --test tests/rule_order.test.js tests/html_security.test.js tests/network_settings.test.js tests/template_session.test.js tests/agents.test.js tests/managed_nodes.test.js
python scripts/check_repository_privacy.py
```

新增演练验证：无 DB 的文件配置首次启用控制面后字节不变；冷恢复保留节点/历史/凭据/撤销；未完成任务重领及旧租约拒绝；缺失/错配 key 拒绝解密且不重建；SQLite backup 包含已提交 WAL、排除未提交修改。全部使用临时合成数据。

已有迁移故障测试见 `test_deployments.py`、`test_landings.py`、`test_chains.py`；模板中断恢复见 `test_template_revisions.py`。CI 另跑固定 Mihomo 解析与真实 sing-box/systemd 的激活、端口冲突回滚、Reality TCP/UDP → SS2022 和移除。

待目标环境执行的项目：生产备份恢复演练、镜像构建与启动、真实公网入口/落地连通性、实际使用的 OS/架构安装验证。当前没有完整 Debian/Ubuntu × amd64/arm64 特权安装矩阵证据；依赖和镜像输入已锁定，仍不能称为镜像逐字节可复现；见[依赖锁说明](DEPENDENCIES.md)。

## 9. Controller 上线操作

非 root 版本使用10001:10001，必须在下面冷备完成后、启动新镜像前执行[数据权限迁移](CONTAINER_PERMISSIONS.md)。回滚同时恢复旧 Compose/覆盖文件与数据备份。

以下是 Linux Docker Compose 的操作模板。替换路径和发布提交，核对实际挂载与 Compose 覆盖文件后执行；不应原样用于未知机器。工作树有本地改动时先保留并审查，不运行 `reset --hard`。

1. 确定 CI 全绿且已审查的完整提交。记录旧提交、当前容器镜像 ID、服务状态和有效挂载；保留旧镜像标签。用 `docker compose config --quiet` 检查配置，避免输出展开的环境变量。
2. 准备仓库外仅管理员可访问的备份父目录；第 4 步在其中创建本次目录。在冷备完成前保留旧 checkout、Compose 与 `.env`；不要先拉新代码覆盖回滚基线。镜像标签变更不应导致旧镜像被清理。
3. 安排短暂停机窗口。等待当前部署任务完成，停止所有 Controller 写入者；对需要回滚协调的 Agent 先暂停同步。仅停止 `proxyforge` 服务，确认容器确已停止。
4. 冷备整个数据目录，并校验备份可读取。示例（同一个 Bash 会话）：

   ```bash
   set -euo pipefail
   umask 077
   cd /srv/ProxyForge
   backup_dir=$(mktemp -d /srv/proxyforge-backups/release-XXXXXXXX)
   # 父目录应事先创建为仅管理员可访问。
   git rev-parse HEAD > "$backup_dir/code-at-backup.txt"
   cp -- .env docker-compose.yml "$backup_dir/"
   # 有覆盖文件或外部秘密文件时，按实际配置补充保存。
   docker compose stop proxyforge
   container_id=$(docker compose ps -aq proxyforge)
   test -n "$container_id"
   test "$(docker inspect --format '{{.State.Running}}' "$container_id")" = false
   docker inspect --format '{{.Image}}' "$container_id" > "$backup_dir/image-at-backup.txt"
   tar -cpf "$backup_dir/data.tar" data
   tar -tf "$backup_dir/data.tar" > /dev/null
   sha256sum "$backup_dir/data.tar" > "$backup_dir/data.tar.sha256"
   ```

   此代码片段仅执行冷备，记录的是更新前的回滚基线。停止后任何步骤失败时，先判断代码/镜像/数据当前状态，再选择恢复旧服务，不能无条件启动候选版本。
5. 冷备完成后将干净 checkout 快进到已验证的固定提交，保留站点自己的 Compose/环境配置，并构建候选镜像；本流程的停机窗口包含构建和演练时间。将备份解包到新的隔离目录，在无外部网络且不能接受 Agent 请求的环境使用候选镜像验证迁移、DB integrity/FK、密钥解密、模板及订阅生成。演练仅可修改副本，输出计数/状态，不输出内容。不能让恢复副本与生产同时向同一批 Agent 发任务。
6. 演练通过后核对生产 checkout 和候选镜像确实对应目标提交。执行 `docker compose up -d --no-build --no-deps proxyforge`，按第 3 节验证 HTTP/权限/模板/订阅，再检查容器运行状态与重启计数。随后逐台恢复 Agent 同步并检查任务结果。
7. 保留备份与旧镜像到验收窗口结束。发布记录只写提交、镜像 ID、schema、检查结果、回滚位置；不写凭据、订阅全文或私有节点配置。

## 10. 完成标准与范围

代码交付完成需要本 PR 的 Python/Node、隐私检查、Mihomo 和真实 runtime CI 通过。生产发布完成还需要第 9 节在目标环境完成并保存验收记录；这两种状态必须分开报告。本阶段不增加批量部署、轮换、远程卸载、自更新或新协议。

## 11. 迁移边界

无控制面 DB 的旧部署保持文件配置；首次使用控制面时创建 schema 5。已有 schema 1–4 在事务中迁移，失败回滚；超过 5 则拒绝启动该存储。迁移只升级结构，不证明远端 Agent 或协议支持同步升级。

旧客户端无 `expected_revision` 的模板写入返回 428，用户应刷新到配套前端；过期 revision 返回 409。不要以删除字段校验或自动重试覆盖的方式绕过保护。

## 12. 回滚

仅从 B6 回到 B5b：schema 都为 5，可还原 Controller 与完整 static；不需要降低 DB 版本。

回到更早 schema 或恢复旧时间点：先停止 Controller 和 Agent 同步，私密归档失败版本的全部数据、任务/receipt 与事务状态。将成套旧备份恢复到新目录并核验，保留现有目录后再切换挂载；不要覆盖混合新旧 DB/WAL/key，也不要手改 `schema_migrations`。还原对应旧代码、Compose 和已保留镜像，不临时重新构建一个未知的“旧版本”。

恢复 Controller 不会撤销已执行的远端部署。先核对并收敛所有入口/落地的真实运行状态，再恢复同步；必要时按各阶段恢复说明先使用新版本完成链路移除或事务恢复。旧版本不认识的新动作日志必须私密归档，不能删除后假设未执行。
