# Agent B1：架构与验收（历史阶段）

本文记录 B1 引入清单与心跳时的设计；其中 schema 1、无任务/部署等限制仅指 B1。当前为 schema 5、Agent 0.6.0，后续能力见 B2–B6；新安装使用[完整安装命令](AGENT_INSTALL.md)，升级、备份和回滚以[发布验收](RELEASE_ACCEPTANCE.md)为准。

## 1. 修改组件

`proxyforge/control/control_store.py` 引入 SQLite 清单存储和迁移；`proxyforge/control/agent_api.py` 分离管理、注册、心跳路由并限制请求结构。`agent/` 包含仅用标准库的客户端、只读清单采集、本地安装脚本和 systemd unit。`static/agents.js` 提供清单管理界面，`main.py` 负责接线，导入/生成订阅时不打开控制数据库。协议模型使用 Pydantic 2。

## 2. 数据模型

B1 使用本地 `data/proxyforge.db`，schema 1：

| 表 | 用途 |
| --- | --- |
| schema_migrations | 已应用的整数版本；拒绝比代码更新的 schema |
| registration_tokens | ID、SHA256 摘要、指定显示名、创建/到期/消费时间 |
| agents | ID、独立实例 ID、名称、元数据 JSON、观察到的 IP、创建/最后心跳/撤销时间、角色与标签 |
| agent_credentials | 每台 Agent 的凭据摘要、创建/撤销时间及 agents 外键 |
| audit_events | 事件类型、可选 Agent ID、时间；只保留最新 1000 条 |

凭据使用 256 位随机数，只在签发/注册响应中返回明文，Controller 不保存明文；Agent 须私密保存自身长期凭据。SQL 使用参数化语句。元数据有大小限制、拒绝未知字段，属于机器自报清单而非可信证明；角色不决定部署行为。

SQLite 启用外键、WAL、5 秒 busy timeout，每次操作使用独立连接和短事务。消费注册凭据、创建 Agent 和长期凭据在同一事务；心跳鉴权和写入相对于撤销也是原子的。最多 100 条未消费且未过期注册记录、1000 台 Agent；签发新凭据时清理过期注册记录。不保存指标历史。

## 3. API

以下管理接口均要求既有管理鉴权：

| 方法与路径 | 行为 |
| --- | --- |
| POST /api/agents/registration-tokens | `{name}`；只返回一次注册凭据及到期时间，有效期 10 分钟 |
| GET /api/agents | 公开清单字段、推导的在线状态和兼容性 |
| GET /api/agents/{id} | 详情，不含凭据或摘要 |
| PATCH /api/agents/{id} | `{name, role, tags}`；只修改清单标签 |
| POST /api/agents/{id}/revoke | 立即撤销该 Agent 凭据 |
| DELETE /api/agents/{id} | 撤销并移除清单，不执行远程卸载 |

机器接口独立鉴权：

- POST `/api/agent/register`：提交 `registration_token` 和清单，返回 `agent_id`、`agent_token`、`protocol_version`、`heartbeat_interval`。Cookie/管理身份不能替代注册凭据。
- POST `/api/agent/heartbeat`：使用独立 Agent Bearer 凭据提交清单，返回状态、兼容性、Controller 协议版本和心跳间隔。身份由凭据确定，不接受客户端指定 `agent_id`。

Agent 与 Agent 管理请求正文上限 16 KiB。无效结构返回不回显输入的通用 422；无效/撤销凭据返回 401，达到容量上限返回 429，SQLite 故障返回通用 503。注册失败使用有界的进程内全局限速器：每分钟 20 次失败、封禁 60 秒。它不是分布式 DDoS 防护，仍须反向代理请求大小和时间限制。不要记录 Authorization 或请求正文。

## 4. 鉴权边界

管理、订阅、Agent 凭据相互独立。Agent 凭据不能读取管理清单、模板或订阅秘密，也不能指定另一身份。所有 Agent 操作检查撤销状态。管理 Cookie 保留同源写入检查，不能充当 Agent 身份。

TLS 验证系统/显式私有 CA，不默认跳过证书验证。HTTP 仅为显式开发选项。客户端禁止重定向及隐式代理环境继承。部署须自行提供 HTTPS；本阶段不修改服务器反向代理。

## 5. 协议

清单协议 1 的心跳包含 `instance_id`、hostname、哈希后的 machine_id 提示、系统/版本、架构、Agent 版本、协议版本、uptime、addresses（参考客户端当前为空）、supported 标记与独立 sing-box 运行状态。不包含 CPU/RAM 指标或部署秘密。

观察到的 IP 来自 ASGI 请求客户端，须正确配置可信反向代理转发。界面只将它显示为连接来源，不自动用作公网节点地址。不兼容协议仍可见；B1 不下发动作。

## 6. 状态机

注册凭据：issued → consumed，或 expired；同一凭据只能被一个事务消费。响应丢失后**不能幂等重放注册**：检查并移除孤儿清单记录，签发新凭据后重新登记。本地待注册配置不含注册或长期凭据；客户端只调用一次注册接口。

Agent：never_seen → online（<90 秒）→ degraded（<300 秒）→ offline；任意状态可撤销/移除。last_seen 使用服务器收到心跳的时间。心跳失败采用有界指数退避和抖动；鉴权拒绝退出码为 4，systemd 不对该退出码重启。

## 7. 任务结构

B1 不含 jobs 表、轮询接口、exec API、deployment.apply、服务变更、防火墙操作、浏览器终端或 Agent 自升级。这是历史范围，后续允许列表任务见 [B2](AGENT_B2.md)。

## 8. 测试与实际验证

存储测试覆盖并发单次消费、过期、哈希存储、时钟阈值、实例绑定、持久撤销、删除和迁移版本拒绝。API 测试覆盖所有凭据边界、自身/其他 Agent 越权、Cookie 隔离、正文限制、未知字段、日志/响应脱敏和协议不匹配。真实参考 Agent 在本机开发 HTTP 服务完成注册与心跳，撤销后停止。

模板并发/历史、Python/Node 和真实 Mihomo 生成 CI 继续作为门禁；安装脚本检查 Bash 语法。B1 未执行全部 Debian/Ubuntu、arm64 的特权安装矩阵；最新实测范围另见[安装指南](AGENT_INSTALL.md)。

## 9. 安全措施

不持有 VPS SSH 凭据，不开启入站监听。服务使用专用非特权账户、私有文件、systemd 加固和固定只读探测命令。凭据从隐藏终端/标准输入传入，不使用命令行参数。B1 不远程下载/执行脚本、不安装 sing-box；界面通过 textContent 展示清单，使用管理鉴权，并在关闭弹窗时清空注册凭据。

## 10. B1 当时未包含的范围

任务/租约、部署模型、密钥生成、VLESS Reality、SS2022 链路、托管节点投影、签名分发/更新、完整系统/架构安装验收和分布式 Controller。这些能力须经后续独立审查，不能用占位动作冒充实现；当前进度见[开发计划](NEXT_STEPS.md)。

## 11. 迁移与备份

只有新增控制面状态进入 SQLite，既有模板、机场、自建节点与原凭据不变。schema 迁移是事务性的，拒绝静默降级。首次使用清单 API 时才初始化数据库，普通订阅生成不依赖它。

使用 SQLite backup API，或停服后保存完整一致的运行状态。不要仅复制运行中 WAL 数据库的主文件。DB、WAL/SHM 和备份含敏感清单，必须限制访问。

## 12. 回滚

回滚到 B1 之前的 Controller 后，原 YAML 仍可使用，Agent DB 保留在磁盘；旧代码没有 Agent 接口。重新升级前停止 Agent，或先撤销凭据。B1 本身不修改 sing-box。若将来返回同一 DB，应私密保留 Agent 凭据；DB 恢复后核对撤销状态，必要时轮换/重新登记。不要通过删除运行数据回滚代码。仅供本机的 MEMORY.md 不进入发布产物或 VPS。

参考：[SQLite WAL](https://www.sqlite.org/wal.html)、[SQLite 备份 API](https://www.sqlite.org/backup.html)。
