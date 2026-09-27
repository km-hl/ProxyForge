# B5b：入口与 SS2022 落地链路

入口已有 VLESS Reality 直连部署、另一 Agent 已有 SS2022 落地部署时，可以添加独立链路监听。直连的端口、UUID、密钥、名称和客户端节点保持不变。链路使用另一个端口和独立 Reality 凭据，成功后发布第二个客户端节点。

## 1. 修改文件

- `proxyforge/control/chain_store.py`、`proxyforge/control/control_store.py`：关系、加密快照、事务与迁移。
- `proxyforge/control/deployment_api.py`、`proxyforge/control/deployment_store.py`、`proxyforge/control/job_store.py`：管理 API、依赖保护、节点投影和队列。
- `agent/chain_spec.py`、runtime、inventory、installers：受控配置生成、能力门控和执行。
- `static/agents.js`：链路创建、状态、重试与移除。
- `tests/test_chains.py`、`scripts/check_ss2022_chain.py`：存储/API/运行恢复与真实转发。

## 2. 数据模型

SQLite schema 5 新增 `chains`：id、唯一入口 agent_id、landing_agent_id、公开 settings、revision、Fernet secret_spec、最新 job_id、updated_at。外键关联 Agent；旧 deployments、凭据和修订原样保留。每入口最多一条链路，名称和落地绑定创建后固定；一个落地可以供多个入口使用。

链路快照包括原直连完整规格、新入口完整规格、落地规格。加密使用现有 `data/deployment.key`，任务快照不可变。移除任务只下发直连规格，同时保留链路凭据用于重新启用。

## 3. API

所有接口位于管理员路由：

- `GET /api/agents/deployments/landings`：已成功部署且未撤销的落地候选，仅 ID/名称。
- `GET /api/agents/{entry_id}/chain`：`{chain: null | ...}`，不含凭据。
- `PUT /api/agents/{entry_id}/chain`：如下。

```json
{
  "request_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_revision": 0,
  "landing_agent_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "settings": {"name": "入口经落地", "listen_port": 8443},
  "remove": false
}
```

创建 revision 0，后续使用当前 revision 和新 request_id；相同最新请求幂等。remove 使用保存的 settings 和落地 ID。返回 id/agent_id/landing_agent_id/settings/revision/job_id/action/status/error/updated_at。端口不能等于原直连端口；额外字段、密码、JSON 配置和任意命令不被接受。版本冲突、依赖未就绪、活动任务或缺少能力返回 409。

## 4. 鉴权边界

Agent token 不能访问管理接口；只有入口 Agent 可以领取包含链路凭据的任务，其他 Agent 不可领取。订阅只包含两个入口的客户端连接信息，绝不包含 SS2022 密码或 Reality 私钥。链路详情、任务列表、审计、错误和 Agent journal 不含这些秘密。

凭据撤销始终可执行，但不会停止远端监听；关联未解除时禁止删除 Agent 记录。撤销落地会撤下相关链路订阅，仍允许入口执行 remove。撤销入口后无法再通过旧 token 移除链路；应先移除再撤销。紧急撤销后的遗留监听需要本地管理员关闭，相关依赖保留等待恢复处理，不提供绕过保护的强制删除 API。

## 5. Agent 协议

Agent 0.6.0，新增 `chain_protocol_version=1`（缺省 0）。入口需 runtime capability 1、chain capability 1、受支持平台和 job protocol 1。落地沿用 B5a，无需链路执行能力。新能力须在完成 helper/模块升级后由 root 创建 `/opt/proxyforge-agent/chain-protocol`，内容 `1`，0644；Agent 同时验证 root-owned socket 与标记权限。

## 6. 状态机与依赖

先部署成功落地和直连，再关联入口，避免尚未就绪的目标被发布。一次 SQLite 写事务串行化关联和两个部署的修改。关联存在时锁定入口与落地的部署修改/移除，直到 `chain.remove` 成功；失败、超时、取消均不解除锁，因为远端可能已经提交。

链路 pending/failed/cancelled/remove 不发布链路节点，但稳定名称继续保留，现有模板引用按照 B4 的规则生成 REJECT，不改写模板。直连节点继续发布。移除只关闭链路监听、保留直连；需调整入口公网地址/SNI或落地参数时，先移除所有相关链路，再修改部署，再重新应用链路。

多个 Agent 无法提供原子远程事务，本阶段采用已就绪落地 + 入口单实例原子切换。成功仅表示本地配置通过检查并运行，不是公网连通性或持续健康证明。

## 7. Job schema 与运行配置

新增 `chain.apply` / `chain.remove`，公开 payload 继续为 `{deployment_id,revision,spec_hash}`，其中 deployment_id 标识 chain；外层修订绑定 job ID/type/payload。解密规格 `{direct, chain}`：apply 的 chain 为 `{entry,landing}`，remove 的 chain 为 null。普通 jobs POST 不允许构造这些动作。

helper 验证严格 schema、hash、独立端口/UUID、相同公网地址/SNI；组合两个 Reality inbound。`managed-chain` 明确路由至 SS2022 outbound，原 `managed-vless` 仍直连。落地连接失败不会回退直连。SS2022 域名通过固定 system local DNS resolver 解析，不允许管理员提交任意 resolver 参数。使用 pinned sing-box 1.14.2、原子切换、实际进程/双监听检查、恢复、receipt 重放；服务权限不增加。

[sing-box Route Rule](https://sing-box.sagernet.org/configuration/route/rule/) 和 [Dial Fields](https://sing-box.sagernet.org/configuration/shared/dial/) 是配置字段依据。

## 8. 测试

覆盖直接/链路节点并存、秘密脱敏、错误能力、任务隔离、并发关联/落地修改、版本/端口冲突、取消/失败后的依赖锁、成功移除释放依赖、撤销后的节点撤回、保留期不清理当前任务、schema 4 迁移与中断回滚、Linux 运行恢复和重放。

真实集成使用官方二进制、systemd 入口、独立 SS2022 落地进程及本机 echo。生成配置先交给真实 parser 检查（包括域名落地配置），然后仅将 Reality 伪装握手目标换为本机临时 TLS 1.3 服务；其余入站认证、路由和 SS2022 数据路径保持生成结果。验证双节点 TCP/UDP、落地停止后链路失败而直连可用、端口冲突回滚、移除后直连保留。临时证书/配置/进程清理，不访问公网业务目标。

## 9. 安全措施

独立入口凭据，CSPRNG 生成，Fernet 加密，配置/事务文件权限沿用 B3/B4。没有 SSH、任意 shell、任意文件路径、密码输入、TLS 验证关闭或防火墙修改接口。落地单用户密码会授权给所有关联入口；各入口能访问同一落地，当前没有入口间独立 SS 用户隔离。移除链路不等同于撤销此前下发的 SS 密码。

## 10. 未实现内容

每入口多链路、同 Agent 同时充当落地和入口、修改落地绑定、自动全量编排/重试、端到端持续探测、凭据轮换/每入口落地用户、远程防火墙与 ACL、紧急撤销后的远程清理、完整托管 Nodes 管理 UI、全部 OS/arm64 安装矩阵。节点页仍为已有只读投影。

## 11. 迁移与升级

停止 Controller 并一致性私密备份 data（SQLite/WAL/SHM 和 deployment.key），先升级 Controller；schema 4→5 同一事务建表，不解密改写旧数据。等 Agent 活动任务结束，停止 Agent/socket/helper，从同一个已审查 checkout 升级安装脚本列出的全部模块，包含 chain_spec.py，确认 root-owned 且普通用户不可写，再创建 chain-protocol 标记并启动。不要只写标记或覆盖部分模块，不重跑拒绝已有路径的 fresh installer。

## 12. 回滚

单次应用失败恢复上一版入口配置。手动恢复参数使用新修订，不降低 revision。降级前成功移除所有链路，停 Agent/helper，使用 B5b 恢复未结束 chain transaction 后再恢复旧模块，移除 chain-protocol 标记并私密归档新动作 journal。B5a Controller 拒绝 schema 5；停止同步后恢复一致性的升级前 DB/key/代码，禁止手动调低版本号。控制面回滚不会停止远端遗留服务。

MEMORY.md 始终仅本地忽略，不进入 Git、镜像或 VPS。
