# B3：独立 sing-box 托管运行环境（历史阶段）

本文记录 B3 的固定版本安装、启动/停止/重启及回滚。初始配置没有入站，不开放公网代理端口；Reality、SS2022 和节点投影属于后续 B4–B6。已有 `/etc/sing-box` 和 `sing-box.service` 不被接管或修改。本文的 schema 2、Agent 0.3.0 和无低端口能力均为历史阶段边界；当前安装/升级以[安装指南](AGENT_INSTALL.md)和[发布验收](RELEASE_ACCEPTANCE.md)为准。

## 1. 文件与组件

标准库 Agent 增加 `runtime_spec`、`runtime_download`、`runtime_engine`、`runtime_client`、`runtime_helper` 和 `job_lease`。已审查的版本清单为 `agent/singbox-release.json`。独立的本地可选安装器与三个 systemd unit 配置 helper 和隔离运行环境。Controller 模型、队列和 UI 只开放新增允许列表动作。`scripts/check_singbox_runtime.py` 在一次性主机用官方二进制和真实 systemd 验证；单元测试覆盖旧租约隔离、权限、崩溃恢复和畸形下载。

## 2. 存储与所有权

B3 维持 schema 2，使用既有不可变 job type/payload/revision 保存运行环境请求，无新增表或旧 YAML 迁移。Controller 对规范 JSON `[job_id, type, payload]` 计算 SHA256，作为 `deployment_revision`。同一 request ID 改变内容会冲突；该字段此时表示操作修订，而非节点部署/配置修订。

Agent 仍只拥有 `/etc/proxyforge-agent` 和私密日志。root helper 将不可变代际保存在 `/var/lib/proxyforge-runtime/releases/{job_id}`，使用原子 `current`、`previous` 符号链接。每代包含二进制、`config.json` 和版本元数据。配置为 root 所有、0640，专用 `proxyforge-singbox` 组可读；目录/二进制可遍历/执行，但 Agent 和 runtime 用户均不可写。intent/receipt 仅 root 可访问。操作成功后仅保留 current/previous 两代和最多 128 条 helper receipt。

配置没有放入早期计划的 Agent-owned `/etc` 目录：root helper 不能经由 Agent 可控父目录写文件。安装器创建 `/opt/proxyforge-agent/bin/sing-box` 符号链接供只读探测；调用者不能向特权代码传任意路径。

## 3. API

管理接口 `POST /api/agents/{id}/jobs` 接受以下动作。客户端提交 `deployment_revision: null`，服务器生成不可变操作修订。既有幂等 request_id、列表和取消 API 不变。

| type | payload | 行为 |
| --- | --- | --- |
| `singbox.status` | `{}` | 既有只读状态查询 |
| `singbox.install` | `{"version":"1.14.2"}` | 安装/更新固定版本，校验并确保运行 |
| `singbox.start` | `{}` | 确保已安装实例运行 |
| `singbox.stop` | `{}` | 确保已安装实例停止 |
| `singbox.restart` | `{}` | 为当前二进制/配置创建并激活新的不可变代际 |
| `singbox.rollback` | `{}` | 复制上一代并激活，保留当前运行/停止状态 |

已健康运行时 start、同版本且健康的 install 不产生变更。显式 restart 创建新代际。rollback 要求存在 previous；重启之后前后可能是同一上游二进制版本，因此 UI 的“上一运行环境版本”不承诺回到不同上游版本。

`GET /api/agents/runtime/release` 返回固定版本。机器接口 `POST /api/agent/jobs/{id}/renew` 接收当前 `lease_token`，返回新到期时间。凭据、归属、能力、期限和当前租约在事务中校验；续租不能复活已过期、取消或完成的尝试。

## 4. 特权与鉴权边界

Agent 仍以 `proxyforge-agent` 运行，不新增 root/sudo 权限。可选 helper 经 `/run/proxyforge-runtime.sock` 激活：root 所有、Agent 组、0660。Linux SO_PEERCRED 仅接纳 Agent UID，客户端同时检查对端为 root。helper 不监听 TCP；消息上限 8 KiB，双向检查动作/revision/result 结构，不接受 URL、可执行路径、配置 blob、用户名、shell 参数或服务名。

root 操作限于专用 release 树和固定 systemd unit。代码、包及所有父目录须 root 所有且不可被组/其他用户写入，Python 以隔离模式运行。helper 的 systemd 文件系统沙箱仅允许写其 runtime 目录；systemctl 经系统管理器操作固定 unit。这是管理员授权的信任边界：被攻陷的已授权 Agent 能控制该专用实例，但接口不提供通用 root 命令或任意文件写入。

B3 的 sing-box 进程使用独立非特权账户、空 capability 集、NoNewPrivileges、ProtectSystem=strict、ProtectHome 和 PrivateTmp；当时不支持低端口、TUN、路由或防火墙变更。B4 后续单独增加低端口所需能力。

## 5. 协议与兼容性

Agent 0.3.0 保留清单/任务协议 1，新增 `runtime_protocol_version`。缺省 0 让 B1/B2 仅具有清单/只读能力；B3 仅在 root-owned helper socket 存在时声明 runtime 1。管理创建、领取和上报还须 runtime 1 及受支持平台。socket 存在表示已选择启用，不代表健康；helper 不可用会产生固定失败。

先升级 Controller，旧 Controller 会拒绝新增元数据字段。目标矩阵为 Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64；helper 独立检查系统/架构。不宣称全部组合都已完成安装验收，不支持的平台仍可上报清单。

## 6. 状态、租约与中断

沿用既有队列状态、期限及最多三次尝试。helper 工作时，Agent 独立线程每 10 秒续租并发送心跳；续租失败、拒绝/撤销或 40 秒未获得确认会关闭 helper 连接。helper 在下载期间和激活前检查连接是否存活。下载预算 5 分钟，helper 操作在检查点执行 10 分钟预算限制；子进程另有超时。

取消是在激活前尽力阻止执行，不是分布式事务回滚。最终检查之后到达的取消可能与已开始的 systemd 操作竞争：远端可能完成，Controller 却拒绝结果。发下一操作前刷新状态。helper 用本地进程锁串行处理，不并发激活文件。

切换前，helper 持久记录旧 current/previous 目标及运行状态；校验准备好的配置、切换链接、启动固定服务，并同时检查 active 状态与 `/proc/MainPID/exe` 是否对应预期不可变二进制。激活成功后进程崩溃，恢复可通过该路径识别已完成状态，不再次重启。未完成激活恢复旧指针和原运行/停止状态；回滚失败保留 intent 供本地修复，并阻止继续修改。

receipt 持久化后即视为已提交，即使结果响应丢失。Agent 日志与 helper receipt 可重放重复结果；但人工删除、DB 恢复、receipt 淘汰或外部服务变更后，不承诺恰好执行一次。

## 7. 结构与下载信任

固定 sing-box 1.14.2，来源为[官方 Release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2)。清单记录 GitHub 公布的 linux-amd64、linux-arm64 归档 SHA256；更新须经代码审查，不接受 latest、自定义版本或 Controller 提供的下载 URL/hash。HTTPS 使用系统 CA，仅允许跳转到 GitHub release 资产主机，忽略代理环境，限制下载/归档大小。

先验证 hash，再复制唯一预期的普通二进制成员，不做通用归档解包。拒绝二进制符号/硬链接、重复或缺失成员。激活前以隔离 runtime 用户运行 `sing-box check` 并检查精确版本；CLI 依据见[官方配置文档](https://sing-box.sagernet.org/configuration/)。下载、检查或激活失败不发布半成品。

结果复用有界状态结构，错误只使用 `runtime_unavailable`、`runtime_failed`、`runtime_cancelled`、`rollback_failed`；任意 stderr、下载 URL、路径或配置内容不传回 Controller/错误日志。

## 8. 验证

测试覆盖不可变动作修订、幂等键内容变化、能力门控、续租归属/撤销/期限、helper 对端身份、畸形归档、校验失败、无变更安装/启动、重复投递、中断准备/激活、健康检查及回滚失败。Linux 文件系统测试在 Linux 运行、Windows 跳过。

专用 CI 下载固定官方 amd64 二进制，执行真实配置检查和 systemd 启动、重启、停止、重放、回滚；拒绝已有 runtime 账户/unit，只清理自身的一次性资源。既有 Mihomo CI 保留。

## 9. 部署与本地显式启用

B3 当时的升级顺序为 Controller → Agent 0.3.0；当前请使用已审查的配套版本。首次 `agent/install.sh` 只安装非特权 Agent，欲启用 runtime 管理，在目标机器审查源码后本地运行：

```bash
sudo bash agent/install-runtime.sh
```

脚本拒绝已有 runtime 路径/unit，不覆盖其他服务。它创建隔离账户、固定 units、runtime 目录和 socket，尚不下载 sing-box。能力出现后，在“Agent 服务器 → 任务”选择固定版本安装。

start/stop 改变运行状态，unit 仍保持 enabled 以便重启恢复；stop 不等于永久禁用服务。要跨重启保持停止，应在本地禁用专用 unit。安装成功后以零入站配置启动。

## 10. B3 当时未包含的范围

节点/部署模型、秘密生成、Reality、SS2022、代理监听、自定义 JSON 编辑、自动防火墙、任意版本选择、上游自动升级、Agent 入站访问和托管节点投影。B3 基础运行环境不生成订阅节点；后续部署能力见 B4–B6。

## 11. 备份与升级

一致备份 Controller SQLite，私密备份 Agent 凭据/日志及完整 root-owned runtime 目录，保留符号链接和所有权。文件系统备份前停止 Agent、helper，确保没有激活进行中。升级已安装包须停相关服务，并从同一可信版本安装全部文件；不要原地替换正在运行的 root helper 代码。不提供远程 helper/Agent 自升级。

## 12. 回滚与恢复

普通 runtime 回滚使用结构化任务，激活前检查旧配置/二进制；健康检查失败会恢复原活动状态。若 `rollback_failed`，本地停止 Agent/helper，保留目录并检查专用 unit，再恢复一致备份；不能删除 intent 或链接绕过恢复。不提供宽泛卸载/删除 API。

Controller/Agent 回到 B2：停止 Agent、helper/socket，取消未完成 runtime 任务，备份现状，再恢复匹配的代码。schema 2 不变，但 B2 不认识 runtime 动作/日志；运行前私密归档 B3 Agent 日志，保留 helper receipt 和托管文件以备重新升级。不要静默重置凭据、删除 runtime 代际，或假定 DB 恢复能保留之后的撤销。回到 B1 仍需 schema 2 之前的 DB。MEMORY.md 不进入 Git 或 VPS。
