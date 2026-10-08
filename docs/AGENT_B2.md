# B2：带租约的 Agent 任务协议（历史阶段）

本文记录 B2 通过只读 `singbox.status` 建立结构化队列时的设计。B2 不接受安装、重启、部署或任意命令；后续可写操作见 [B3](AGENT_B3.md) 至 B5。当前安装与升级请使用[发布验收流程](RELEASE_ACCEPTANCE.md)，不能把本文的 schema 2、Agent 0.2.0 当作当前版本；代码交付不等于生产部署。

## 1. 文件

`proxyforge/control/job_store.py` 实现事务队列；`control_store.py` 负责 SQLite 迁移及撤销时取消活动任务；`job_api.py` 定义严格结构和路由，由 `agent_api.py` 接入。`agent/jobs.py` 实现允许列表、本地进程锁与结果日志。传输、主循环和安装器加入任务协议；`static/agents.js` 提供创建、状态和取消界面。测试与 CI 同时保留既有配置/Mihomo 检查。

## 2. 数据模型

schema 2 新增 `jobs`，按 Agent/状态/时间建立索引。每条任务包含 UUID、目标 Agent、管理员请求 UUID、动作、不可变 payload 与 deployment revision、状态、创建/期限/分配/开始/结束时间、尝试次数、租约凭据哈希/到期时间、结构化结果和固定错误码。`(agent_id, request_id)` 唯一；删除 Agent 级联删除任务，撤销保留历史并取消未完成任务。既有 YAML 不变。

每台 Agent 最多 20 个未完成任务，全局最多保留 10000 条。创建时清理超过 7 天的终态记录，否则达到容量上限返回 429。管理列表返回最新 100 条，不暴露租约凭据/哈希。创建幂等键只在记录保留期内有效；复用已删除/过期记录的键可能创建另一次只读查询。

## 3. API

正文沿用 16 KiB 上限和通用 422 错误。

| 方法与路径 | 请求／响应 |
| --- | --- |
| POST `/api/agents/{agent_id}/jobs` | `request_id` 为 32 位小写十六进制，`type: "singbox.status"`、`payload: {}`、`deployment_revision: null`；返回任务 |
| GET `/api/agents/{agent_id}/jobs` | `{jobs: [...]}` |
| POST `/api/agents/{agent_id}/jobs/{job_id}/cancel` | 返回取消后的任务；重复取消幂等 |
| POST `/api/agent/jobs/claim` | `instance_id`；返回 `{job: null}` 或 `{job: {..., lease_token, job_protocol_version: 1}}` |
| POST `/api/agent/jobs/{job_id}/start` | `lease_token`；返回 running 状态 |
| POST `/api/agent/jobs/{job_id}/result` | `lease_token`、`result`；返回终态 |

领取会改变队列状态，因此使用 POST，不采用早期计划的 GET-next。无任务时返回 JSON 对象而非 204，以适配有界 JSON 传输。无 WebSocket 或 Agent 入站 socket。401 拒绝凭据，404 隐藏其他 Agent 的任务，409 拒绝旧租约、不兼容能力或非法状态转换。

## 4. 鉴权

管理接口沿用管理鉴权。机器接口每次调用（包括结果重放）均须目标 Agent 独立 Bearer 凭据；管理 Cookie/token、注册/订阅 token 均无效。claim 将凭据绑定已注册实例；start/result 同时要求任务归属及本次尝试的随机 256 位租约，Controller 只保存 SHA256 摘要。撤销与任务状态转换共享 SQLite 写事务，进行中的结果不能绕过撤销。

## 5. 协议协商

清单协议仍为 1，新增 `job_protocol_version`，B1 Agent 缺省为 0。B2 Agent 0.2.0 上报 1，Controller 心跳响应也声明任务版本。双方版本匹配后才能创建、领取和提交任务；UI 对缺少能力的 Agent 禁用创建。降级 Agent 的待执行任务等待能力恢复或期限到达。

先升级 Controller：B1 Controller 拒绝新增元数据字段。B1 Agent 可继续向 B2 Controller 发清单/心跳，但不接收可执行任务。不支持的 Linux 发行版仍可显示清单；只读探测不安装软件，运行环境安装的平台限制由后续阶段处理。

## 6. 状态机

`pending → assigned → running → success | failed`；pending/assigned/running 都可转为 cancelled。任务期限 1 小时、租约 60 秒，每台 Agent 同时最多一个租约任务。原子领取增加尝试次数并签发新租约。租约过期将 assigned/running 放回 pending，最多 3 次尝试，之后以 `lease_expired` 失败；总期限到达以 `deadline_exceeded` 失败。claim/create/list 使用服务器时间处理过期，不依赖调度器。上报 `probe_failed` 为终态。

对当前有效租约重复 start 幂等，完成要求 running。完成确认丢失后，以同一租约重复相同结果会返回已有结果，即使原租约已过期；不同结果、旧尝试、已取消或已撤销目标被拒绝。取消不会强制中断机器上已开始的探测。

B2 使用两次各 3 秒超时的固定只读子进程探测，不实现长任务或续租。新增可写动作必须另设计期望状态收敛与续租，不能仅向允许列表追加动作名。

## 7. 任务、结果结构与重放

B2 只接受空 payload、空 deployment revision 的 `singbox.status`。revision 明确保留给后续独立的不可变部署结构。成功为 `status: "success"`、`error: null`，output 含 `installed`、`running`、有界 `version` 和状态枚举；失败为 `status: "failed"`、`output: null`、`error: "probe_failed"`。不接受任意错误文本、stderr、命令、路径或 URL。

Agent 再次校验任务结构，上传前将最近 128 条结果写入私密原子日志。任务身份包含 ID、type、deployment revision，日志另绑定 Controller/Agent/instance。重新下发时用新租约回传已保存结果，不重复探测。日志不保存 Bearer 或租约凭据；每份配置由一个进程持锁。GUI 在不确定重试时保留创建 UUID，直到收到确认；刷新页面会丢失这个内存 UUID，再次创建前应检查列表。

这是有界的至少一次投递，**不保证恰好执行一次**。探测结束但尚未持久化时崩溃、日志淘汰或人工删除，都可能重复只读探测。断连跨越全部尝试或期限时，即使本地已完成也可能最终失败；未来破坏性动作必须自行保证幂等。

## 8. 验证

覆盖并发幂等创建/领取、旧尝试拒绝、重试耗尽、取消/期限、撤销和跨 Agent 归属、能力不匹配、容量限制/清理、DB 升级及迁移失败回滚、严格 payload/result 与秘密不外泄。真实参考 Agent 在回环 HTTP 开发服务上完成注册、心跳、领取/开始/结果和撤销；上传丢失后重领同一任务，验证本地持久结果可避免第二次探测。进程锁与损坏日志检查采取失败关闭；前端能力规则有测试。

既有配置并发/历史及 Mihomo parser CI 保留。B2 不宣称执行完整系统/架构的特权安装或生产部署；各次测试数量和浏览器证据属于对应 PR，最新安装矩阵见[安装指南](AGENT_INSTALL.md)。

## 9. 安全边界

B2 无 shell 动作、SSH、用户可控子进程参数、脚本下载、root 执行器、入站 socket 或关闭 TLS 验证。固定探测只检查 `/opt/proxyforge-agent/bin/sing-box` 与 `proxyforge-singbox.service`，不接管用户运行环境。UI 结果用 textContent；固定错误码避免把 stdout/stderr 或 HTTP 正文写入错误日志。Agent 上报版本/清单仍是受长度限制的不可信数据。

## 10. B2 当时未包含的范围

sing-box 安装/更新/重启、期望状态部署、VLESS Reality、SS2022、托管节点投影、升级分发、长任务续租、指标、WebSocket 与任意执行。运行环境和续租后来在 B3 实现；当前阶段进度见[开发计划](NEXT_STEPS.md)。

## 11. 迁移与备份

schema 1 → 2 在单个事务完成，保留 Agent 凭据和清单；新库事务性创建 schema 1、2，拒绝更新的 schema。部署前停 Controller，私密保存一致运行状态，或对 DB 使用 SQLite backup API；WAL 活跃时不要仅复制主文件。YAML、凭据和 DB 成套保存。需要可预测切换时，备份/升级期间也停 Agent，先升级 Controller 再升级 Agent。不提供自动降级迁移。

## 12. 回滚

仅恢复 B1 Agent 包仍兼容 B2 Controller；保留私密配置/日志，B1 忽略日志。Controller 回到 B1 则须先停 Agent 和 Controller、保存当前现场，再恢复升级前 schema 1 DB 及匹配代码。B1 拒绝 schema 2，修改版本标记或删表不是安全回滚。

恢复 DB 会丢失备份之后的任务、注册和撤销；恢复同步前应核对身份，必要时撤销/轮换。B2 不改变 sing-box 状态。MEMORY.md 继续 Git/Docker 忽略，永不上传。
