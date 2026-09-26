# B5a：SS2022 落地部署

本阶段完成独立 SS2022 落地部署。入口关联和跨 Agent 链路编排在下一 PR 实现；落地不会直接生成客户端订阅节点。现有 VLESS Reality 直连能力保持不变。

## 1. 修改文件

- `agent/landing_spec.py`：SS2022 配置白名单、密码格式检查、运行配置构造。
- `deployment_store.py`、`deployment_api.py`、`control_store.py`：部署协议区分、密码生成/加密、schema 4。
- `job_store.py`、Agent runtime/client/helper、inventory：独立能力、配置快照下发、执行和回传。
- installers、`static/agents.js`：本地能力标记、部署类型选择、落地说明。
- `tests/test_landings.py`、`scripts/check_ss2022_landing.py`：协议隔离、迁移与真实 TCP/UDP 转发、认证、回滚测试。

## 2. 数据模型

`deployments` 增加 `protocol TEXT NOT NULL DEFAULT 'vless-reality'`。旧记录全部保留 VLESS 类型，settings、revision、加密凭据和最新 job ID 不变。新落地记录使用 `protocol='ss2022'`，公开类型为 `singbox_landing`。

每台 Agent 当前仍有一个部署所有者；创建后协议和名称固定。不能将已有 VLESS 部署切换为落地，也不能将落地切换为 VLESS。请为落地选择独立 Agent。本阶段不实现同机多入站；后续链路编排会处理直连与经落地入口并存，不能以覆盖直连配置的方式实现。

## 3. API

沿用管理端 `GET/PUT /api/agents/{id}/deployment`。PUT 增加 `protocol`，缺省为 `vless-reality`，保持旧 VLESS 调用兼容。SS2022 示例：

```json
{
  "request_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "protocol": "ss2022",
  "expected_revision": 0,
  "settings": {
    "name": "Landing B",
    "server": "landing.example.com",
    "listen_port": 8388,
    "method": "2022-blake3-aes-256-gcm"
  },
  "remove": false
}
```

`server` 为将来入口访问落地的明确地址，不从连接来源 IP 推断。当前 UI 建议端口 8388；服务同时监听同端口 TCP/UDP。用户自行配置路由、NAT 和防火墙，本阶段没有远程防火墙动作。

创建使用 revision 0；修改/重试/移除使用最新 revision 和新 request_id。remove 使用相同协议及当前 settings，生成空监听配置并保留凭据和部署记录；重新应用可以恢复。相同最新请求幂等，修订冲突、协议切换、执行中变更返回 409。API 拒绝用户提供的密码、任意配置、路径、URL 或命令。

## 4. 鉴权边界

管理 API 只接受管理身份。只有目标 Agent 的独立 token/instance_id 可以领取解密快照；其他 Agent 无法领取，管理 token 不能作为 Agent token 使用。落地密码不出现在 Agent 清单、普通 Job 列表、部署详情、审计或错误响应中，也不会投影到 `/api/nodes`、模板节点名称清单或订阅。

撤销/移除 Agent 不停止远端 sing-box；要关闭监听，应先执行落地 remove 并确认成功，再撤销 Agent。不要将控制面记录删除视为远程卸载。

## 5. Agent 协议

Agent 0.5.0，新增 `landing_protocol_version=1`，缺省 0。与 Reality 的 `deployment_protocol_version` 分开门控；SS2022 要求 runtime capability 1、landing capability 1 和受支持的平台，不依赖 Reality capability。

升级包和 helper 后，只有固定 root-owned Unix socket 可用且 `/opt/proxyforge-agent/landing-protocol` 是 root-owned、不允许组/其他用户写入、内容为 `1` 的普通文件，才上报落地能力。旧 Agent 不会收到落地任务。Agent 仍只使用 Python 标准库；密码生成使用 Controller 的 `secrets.token_bytes`。

## 6. 状态机

沿用 pending → assigned → running → success/failed/cancelled，以及 B2/B3 租约、续租、deadline、结果重放。修改 settings 保留密码；重试或移除后重新启用也保留密码。失败结果不声称远端已经停止，取消也不保证中断已经开始的切换。

已有任意部署时，通用运行环境变更入口继续禁止绕过期望状态修改实例。使用 apply 更新/重启，remove 关闭监听。Agent role 字段仍是标签，不替代实际部署协议或能力校验。

## 7. Job schema

新增 `landing.apply` / `landing.remove`。公开 payload 为 `{deployment_id,revision,spec_hash}`；外层 deployment_revision 绑定 job ID、type 和 payload。对应 Agent 的领取响应附加 `deployment`：apply 为严格落地规格及 password，remove 为 `{}`。

首次 apply 自动安装固定 sing-box 1.14.2；运行环境复用 B3/B4 的 root helper、独立非 root unit、配置检查、原子切换、PID/exe 与本机 TCP 监听检查、失败回滚和 root receipt。新增动作不增加系统权限；继续只保留低端口所需的 CAP_NET_BIND_SERVICE。持续状态检查不声称完成 UDP 端到端探测。

## 8. 测试

- Controller：独立能力、其他 Agent 隔离、协议不可切换、幂等/版本冲突、密码保持、取消结果拒绝、schema 3 升级及失败回滚、落地不投影节点、VLESS 节点不变。
- 协议/Agent：严格算法与 Base64 密码、快照 hash 绑定、日志不含密码、丢失回传确认后的结果重放。
- Linux engine：首次安装、切换后中断恢复、重复任务、失败恢复旧配置、移除。
- 真实官方 sing-box/systemd：真实客户端经落地完成 loopback TCP/UDP echo，错误密码两种网络均被拒绝，TCP/UDP bind 冲突都恢复上一版，移除释放两种监听；继续运行 B3/B4 的真实集成检查。
- 浏览器：协议选择、SS2022 隐藏 SNI、创建、pending 门控、结果刷新、详情无密码、不生成客户端节点、移除；原 VLESS 页面同时回归。

真实转发测试只访问本机临时 echo 服务，不访问公网业务目标；不等于用户 VPS 的公网连通性或完整 OS/arm64 安装矩阵验证。

## 9. 安全措施

固定 `2022-blake3-aes-256-gcm`，密码为 32 字节 CSPRNG 随机值的规范 Base64；这是 sing-box 文档规定的密钥长度和格式。[官方 Shadowsocks 入站文档](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)

密码使用既有 Fernet `data/deployment.key` 加密写入 SQLite，快照与任务绑定。root transaction 0600，运行配置 root:proxyforge-singbox 0640，Agent 结果日志仅保存身份/hash/固定结果。测试客户端也以隔离用户运行，临时配置受限并清理，测试不自行实现 SS2022 密码算法。

## 10. 未实现内容

入口 → 落地关联、多 Agent 编排、链路状态、同机多入站、落地多用户/按入口凭据隔离、密码轮换、来源 IP ACL、自动防火墙、公网探测和完整托管 Nodes UI。不要把当前 success 当作“入口已接入落地”；它只代表落地任务成功。

## 11. 数据迁移与升级

先停止 Controller 并私密备份完整 data（含 SQLite/WAL/SHM、deployment.key）及代码/镜像，再升级 Controller；schema 3 → 4 在同一事务内增加协议列，不解密或改写旧凭据。

新 Agent 使用更新后的两个本地安装脚本。已有 B4：等活动任务结束，停止 Agent/socket/helper，备份包、凭据和 runtime；从同一个已审查 B5a checkout 更新安装脚本列出的全部模块，特别是新增 `landing_spec.py`。确认包及祖先 root-owned、不可被普通用户写入，随后 root 写入 `/opt/proxyforge-agent/landing-protocol` 内容 `1` 并设置 0644，再启动 socket 和 Agent、检查心跳能力。不要单独把能力标记写到旧 helper 上；不要重跑会拒绝现有路径的 fresh installer。

本阶段没有新增 Python 第三方依赖，也没有改变 B4 的 sing-box unit。

## 12. 回滚

单次应用失败由 runtime 恢复上一版。需要主动恢复参数时，使用最新 revision 重新提交先前 settings，不降低 revision。

B4 Controller 拒绝 schema 4。降级必须停止同步、取消未完成任务并保存当前现场，再恢复迁移前完整一致性 DB/key 与旧代码，不能调低 schema_migrations 数字。降级前先成功 remove 落地监听，或由本地管理员明确接管；控制面降级不会自动关闭遗留服务。

Agent 降级前停止相关服务，移除 landing capability 标记，先由 B5a helper 完成/恢复未结束的 landing transaction，再恢复旧模块并私密归档含 landing 记录的 Agent journal；B4 不认识新动作。保留凭据和受限备份用于恢复。

MEMORY.md 继续仅本地保存，Git/Docker 忽略，永不上传 VPS。
