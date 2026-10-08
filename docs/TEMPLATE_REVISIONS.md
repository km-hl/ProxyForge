# 模板修订与历史（阶段 A）

本文记录阶段 A 引入的模板提交契约，仍用于当前版本；“没有 Agent/SQLite 迁移”等描述仅限定阶段 A 本身，后续 Agent 功能见 B1–B6。当前部署和恢复见[发布验收](RELEASE_ACCEPTANCE.md)。

## 行为与文件

`proxyforge/config/template_store.py` 用可重入线程锁和操作系统文件锁协调模板、节点、机场。`main.py` 路由及启动/订阅清理使用同一锁完成读改写。UI 会话保存最初加载的 revision，`template-history.js` 提供历史、文本比较和显式冲突选择。

MEMORY.md 仅本机使用，被 Git、Docker 构建上下文和隐私门禁排除。

## 数据与持久化

revision 是精确 UTF-8 内容（包括换行差异）的 SHA256。GET 从同一快照读内容和 revision，相同内容保存不产生变更。内容哈希不是单调序号，每条历史另有随机 ID。

成功变更保留基线及新快照于 `data/history/template/<id>.json`，包含时间、revision、大小、来源、正文；GET 不创建快照，恢复是一次重新校验的保存。默认保留 30 条，环境 `TEMPLATE_HISTORY_LIMIT` 限制为 2–100；历史正文总量不超过 32 MiB，每个配置文件不超过 1 MiB。历史属于私密运行数据。

配合此机制的读者都获取 `data/.config.lock`；支持单主机本地文件系统，不保证忽略锁的外部程序安全。既有内存凭据/缓存行为意味着这不等于应用支持多 worker。

私密、已 fsync 的 redo 日志 `data/.config-transaction.json` 是持久提交点。提交之后逐文件原子替换，再发布历史；下一次持锁操作先重放中断提交，再读取。提交点前失败保持原数据；之后失败表示响应结果不确定，不代表回滚。应恢复存储、重新读取后再决定重试，不能删除待处理日志。多文件导入可恢复，并与配合加锁的读者隔离，但不是操作系统级“三文件同时原子 rename”。

## API 与鉴权

接口保留管理 Bearer/session 鉴权，Cookie 写入保留同源检查。

| 方法与路径 | 请求／响应 |
| --- | --- |
| GET `/api/template` | `{content, revision}` |
| POST `/api/template` | `{content, expected_revision}`；返回 `{status, content, revision}` |
| POST `/api/template/validate` | 原校验接口，无需 revision |
| GET `/api/template/history` | 历史元数据，最新在前 |
| GET `/api/template/history/{id}` | 元数据和正文 |
| POST `/api/template/history/{id}/restore` | `{expected_revision}`；按当前节点/providers 校验 |
| POST `/api/template/import` | `{content, expected_revision, nodes, urls}`；校验全部输入并在同一锁下提交三个资源 |

保存/恢复/导入缺少 revision 返回 428，格式错误返回 422，过期返回 409，含 `detail.code=template_conflict`、`current_revision`、`current_content`。协调写入遇到存储故障返回 503，并提示结果不确定。客户端须先 GET 基线；省略 revision 不代表强制覆盖，升级后应刷新旧页面。

节点/机场保存保留既有 API；引用清理与资源修改在同一事务，并返回 `template_revision`。节点/机场列表尚无独立乐观版本。

## 状态与安全

UI 状态为 loaded → editing → saving → saved/conflict/uncertain。冲突保留原草稿基线；查看服务器内容不会静默接受它。重新加载须明确确认丢弃草稿；响应丢失后先检查内容/revision 再重试。历史正文和比较结果均按文本渲染。

全局导入只发一个协调请求，错误时保留输入；不会刷新 revision 后强行提交旧导入。没有自动 YAML 合并。

历史和临时文件使用私有创建权限，ID 经过校验而非直接用作路径；凭据不加入 API 路径或日志。既有 Mihomo 静态门禁和 parser CI 保留。

## Agent、任务与迁移

阶段 A 自身不新增 Agent 协议、任务结构或远程动作。原 YAML/JSON 格式不变，历史、锁和日志按需创建；阶段 A 没有 SQLite 迁移。

## 验证与回滚

覆盖竞争进程与 HTTP 请求、缺少/过期 revision、相同内容无变更、保留上限、基线恢复、路径穿越、提交前失败、中断多文件导入重放、导入校验、间接节点引用清理、前端冲突保留及不确定重试。完整 Python/Node 与真实 Mihomo 生成检查仍必需。

回滚前先用本版本完成日志恢复并做一致备份。旧程序能读同样的 YAML，但不提供并发保护或历史；旧浏览器缺少 revision，无法向新 API 保存。回滚应用代码与恢复运行数据是两件事。

## 阶段边界

阶段 A 不含自动合并、独立节点/机场 revision、分布式文件锁或数据库历史。Agent 注册和远程部署由后续独立阶段增加。
