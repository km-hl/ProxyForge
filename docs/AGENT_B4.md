# B4：VLESS Reality Deployment

本阶段支持每台 Agent 一个直连 VLESS Reality 部署。控制台生成 UUID、X25519 密钥对和 short ID，Agent 在独立 sing-box 实例中应用配置；最新部署成功后，订阅和自建节点列表自动包含客户端节点。无需复制密钥或分享链接。

## 1. 修改文件

- `deployment_store.py`、`deployment_api.py`：加密凭据、期望配置、管理 API。
- `agent/deployment_spec.py`：严格规格、sing-box 配置和 Mihomo 节点生成。
- `control_store.py`、`job_store.py`、`agent_api.py`：schema 3、事务队列、能力门控。
- Agent runtime/client/helper/installers/unit：自动安装、配置应用、TCP 监听检查与低端口能力。
- `main.py`、`static/agents.js`、`static/app.js`：部署入口、自动节点投影、普通节点编辑保护。
- tests、真实运行环境脚本、Mihomo 生成样本和 CI：迁移、隔离、回滚及实际解析验证。

## 2. 数据模型

`deployments`：id、唯一 agent_id、settings、单调递增 revision、secret_spec、最新 job_id、updated_at。settings 只有名称、公网地址、SNI、监听端口。当前一台 Agent 只有一个部署记录，移除监听保留记录与凭据，以便重新启用。

`jobs.secret_payload` 保存该次任务的加密配置快照；普通 payload 只有部署 ID、revision 和快照 SHA256。快照绑定任务，不随之后编辑变化。最新部署所引用的任务不会被七天清理删除，其他任务继续使用 B2 上限和保留规则。

`data/deployment.key` 是 0600 的独立 Fernet 密钥；SQLite 中的 private key、UUID 和完整快照均加密。X25519 和 Fernet 使用固定 `cryptography==46.0.5`，不自行实现密码算法。Windows 部署还应使用服务账户专用目录 ACL；POSIX mode 不能代替 Windows ACL。数据库和 key 一起泄漏仍会暴露凭据。

## 3. API

管理凭据：

- `GET /api/agents/{id}/deployment` → `{deployment: null | summary}`。
- `PUT /api/agents/{id}/deployment` → 当前部署摘要与任务 ID。

请求示例（无密钥输入）：

```json
{
  "request_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_revision": 0,
  "settings": {
    "name": "Direct node",
    "server": "vps.example.com",
    "server_name": "www.example.com",
    "listen_port": 443
  },
  "remove": false
}
```

示例域名只是占位符。使用适合 Reality 的 TLS 1.3 握手目标；填写客户端实际访问的公网 IP/域名，并自行检查 DNS、路由、防火墙和端口映射。本阶段公网端口等于监听端口，不推断 NAT 信息。

`expected_revision=0` 创建；后续更新、重试、移除携带当前 revision 和新的 request_id。名称创建后固定，保证模板引用稳定。相同最新 request_id、settings、expected_revision 和动作可以重放；过时请求返回 409。任务未结束时拒绝新部署变更。`remove=true` 生成空监听配置，保留运行环境，成功后可重新应用。请求不接受任意 JSON 配置、命令、路径、下载地址或用户提供的密钥。

## 4. 鉴权边界

部署管理只接受管理身份；Agent token 不能读写管理 API。只有目标 Agent 使用自身 token、instance_id 领取任务时才能得到解密快照。Agent 列表、部署详情、任务列表、错误响应和审计记录均不返回私钥或 UUID。

客户端节点接口和订阅必须包含连接所需 UUID、公钥和 short ID，沿用现有管理/订阅鉴权；不会包含服务端私钥。撤销/删除 Agent 将撤销凭据并撤回自动节点，不会停止远端监听。需要关闭监听时，应先成功执行移除，再撤销 Agent。

## 5. Agent 协议

Agent 0.4.0；inventory、job、runtime 协议仍为 1，新增 `deployment_protocol_version=1`，缺省为 0。需升级 Controller、Agent 包、root helper 和 sing-box unit。

能力只有在 root-owned Unix socket 和 root-owned、不允许组/其他用户写入的 `/opt/proxyforge-agent/deployment-protocol` 标记存在且内容为 `1` 时才上报。标记由本地安装/升级完成后创建。旧 Agent/旧 helper 无部署能力，不会收到部署任务。

Agent 仍仅使用 Python 标准库；cryptography 仅装在 Controller。配置由 Controller 生成的严格规格派生，helper 使用同一白名单构造器重新校验、生成固定结构，拒绝任意配置注入。

## 6. 状态机

创建/更新事务同时保存期望配置和 pending job；assigned → running → success/failed，取消为 cancelled，租约/期限沿用 B2/B3。只有最新 `deployment.apply` 任务 success 且 Agent 未撤销时发布节点。

更新、失败、取消或移除期间会撤回自动节点，即使远端可能仍在运行上一版。失败不是已停机的证明；应用开始后的取消也不保证远端回滚。重新应用生成新任务来收敛状态。控制台显示的是任务结果，不声称验证了公网端到端可用性。

已有部署时禁止通用 install/start/stop/restart/rollback 修改该实例，避免绕过期望配置导致节点错误。需要重启时重新应用部署；需要关闭监听时执行移除。B4 尚无独立运行环境升级入口。

## 7. Job schema 与执行

`deployment.apply` / `deployment.remove`；payload 为 `{deployment_id, revision, spec_hash}`。外层 deployment_revision 继续绑定 job ID、type、payload；Agent 领取响应附加 `deployment` 快照。helper 校验规格和快照 hash 后才执行。

首次部署自动下载、校验固定版本 sing-box；已有实例复用受控二进制。新配置进入独立 release，使用隔离 runtime 用户运行 `sing-box check`，原子切换 current 后重启固定 unit。健康检查核对实际 PID/exe，并连接本机 IPv6 监听端口。失败恢复旧文件、指针和原运行状态。事务恢复、receipt 重放、续租、断连隔离沿用 B3。

runtime 用户保持非 root；新增且仅新增 `CAP_NET_BIND_SERVICE` bounding/ambient capability，用于 443 等低端口。没有 NET_ADMIN、TUN、透明代理或自动防火墙操作。Reality 为 TCP + `xtls-rprx-vision`，出口 direct。

## 8. 测试

- Python：加密数据和 API 脱敏、密钥丢失失败关闭、能力降级、越权领取、修订冲突、幂等请求、取消结果拒绝、失败不发布、撤销撤回、schema 2 升级和事务回滚、普通节点接口保护。
- Linux engine：首次部署自动安装、切换后中断恢复、receipt 重放、应用失败恢复旧配置、移除。
- 真实官方 sing-box 1.14.2 + systemd：配置检查、低端口监听、重放、真实端口占用后的回滚及监听移除；继续覆盖原运行环境操作。
- Mihomo CI：真实应用生成器加入托管节点投影，由固定官方 Mihomo 解析。
- 浏览器：创建部署、pending 禁止重复修改、结果刷新、自动只读节点、移除；使用临时数据和模拟 Agent 回传，无真实服务器数据。

测试不等于完成所有发行版/arm64 特权安装矩阵，也未验证用户实际 SNI、公网连通性或完整 Reality 客户端握手。

## 9. 安全措施与节点归属

本地 runtime config 为 root:proxyforge-singbox 0640；root transaction 为 0600。Agent 结果日志只保存身份/hash/固定结果，不保存部署快照。服务端密钥不进入 YAML 节点文件，也不进入普通任务详情。

托管节点由 SQLite 当前成功状态动态投影，不写入 `custom_nodes.yaml`，来源字段为 `_managed_by={type,agent_id,deployment_id}`，生成客户端配置时移除全部内部字段。名称附加 `[pf:<deployment_id>]` 防止不同部署重名。普通节点写入接受未变更托管项但忽略其持久化；修改、伪造托管项或占用保留名称返回 409；省略托管项不会删除部署。全量 YAML 导入遵循相同边界。

## 10. 未实现内容

SS2022 落地、链路编排、多入站、多用户、单独密钥轮换、托管名称修改、部署修订历史 UI、独立 runtime 升级、自动防火墙配置、公网探测和自动更新。完整 Agent-managed Nodes 管理页仍属于后续阶段；本阶段提供部署入口和基本只读节点展示。

## 11. 迁移和升级

Controller 首次打开控制面 DB 时，在单个 SQLite 事务内迁移 schema 2 → 3。部署前停止 Controller，私密备份完整 `data/`（包括 DB/WAL/SHM 和 deployment.key，如已存在）、环境配置和代码/镜像。不要运行时单独复制 SQLite 主文件作为一致性备份。恢复有部署的 DB 时必须恢复同一把 key；丢失或错误的 key 返回 503，不重新生成或覆盖。

新 Agent 按 `agent/README.md` 安装，然后本地显式运行 `agent/install-runtime.sh`。已有 B3 Agent 不重跑 fresh installer：先等待任务结束并停止 Agent、runtime socket/helper，备份包、凭据、runtime 和三个 unit；从同一个已审查 B4 checkout 更新所有安装脚本列出的模块（特别是 `deployment_spec.py`），保持包及祖先 root-owned 且不可被普通用户写入。更新 `proxyforge-singbox.service`，执行 `systemctl daemon-reload`。确认这些步骤成功后，以 root 写入内容 `1` 的上述 capability 标记并设为 0644，再启动 socket 和 Agent，检查心跳能力后应用部署。运行中的 sing-box 可在下一次部署重启时使用新 unit 能力。

不要将标记单独复制到旧 helper 安装；标记不是自动升级机制。包升级时停用 helper，避免混用不同版本模块。

## 12. 回滚

单次应用失败由 Agent 恢复上一代；需要主动恢复参数时，以当前 revision 重新提交以前的公网地址、SNI、端口（凭据保留）。配置版本号不回退。

Controller B3 不接受 schema 3。代码降级前停止同步、取消未完成任务、私密备份当前 DB/key；只有恢复迁移前完整一致性备份才能回到 B3，不能修改 schema_migrations 数字。旧 Controller 没有自动节点投影；降级前应成功移除监听，或明确由本地管理员接管遗留监听。

Agent 降级需停 Agent/socket/helper，移除 deployment capability 标记、恢复旧模块和 unit，归档 B4 Agent journal，执行 daemon-reload；旧 helper 不认识 B4 未完成 transaction，因此必须先用 B4 完成恢复。私钥配置和现场资料保留在受限备份，不直接删除。恢复旧 unit 将移除低端口 capability；已有 Reality 部署应先移除或迁移。

MEMORY.md 仅供本地协作，继续被 Git/Docker 忽略，永不上传 VPS。
