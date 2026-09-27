# B6：Agent 托管节点管理界面

自建节点页分别显示手工节点与 Agent 托管节点。托管列表包含直连、经落地、等待执行、失败、已移除和已撤销的记录；修改连接字段通过所属部署或链路完成。

## 1. 修改文件

`proxyforge/control/managed_inventory.py`、`proxyforge/control/control_store.py`、`proxyforge/control/deployment_api.py` 提供管理清单；`static/managed-nodes.js`、app/index/style 实现列表和操作入口；Python/Node 测试及 CI 增加清单、权限和展示验证。

## 2. 数据模型

不新增表，不改变 schema 5 或已有部署/链路。清单读取已有公开 settings、Agent 元数据和最新 Job，不读取或解密 secret_spec。手工节点继续存储于 custom_nodes.yaml，托管记录来自控制数据库。

## 3. API

新增管理员接口 `GET /api/agents/managed/nodes`，返回 `{nodes: [...]}`。每项包括：

- id、kind（direct/chain）、稳定 name、预期 server/port。
- agent 与可选 landing：id/name/status/last_seen/compatible。
- revision/job_id/action/status/error/updated_at。
- removed：最新移除任务成功；publishable：满足已有控制面发布条件。
- blocked_by：修改直连部署前需先成功移除的链路 ID/名称。

`publishable` 不探测公网，不证明客户端已经刷新订阅，也不验证部署密钥可解密。清单读取会在同一事务内处理到期任务，避免必须先进入任务页才能看到失败。

原 `/api/nodes` 和订阅继续只返回符合发布条件的客户端节点；此新清单不能作为订阅配置使用。

## 4. 鉴权边界

沿用管理员路由和请求限制。Agent token、订阅 token 和未认证请求不能读取清单。响应不包含 Agent token、UUID、Reality 私钥、SS2022 密码或加密快照。部署密钥丢失时仍可读取状态以协助恢复。

## 5. Agent 协议

无协议或版本变更，沿用 Agent 0.6.0 能力门控。列表中的管理按钮读取最新 Agent，再打开既有部署/链路/任务页面；实际操作继续由服务器检查能力、版本和依赖。

## 6. 状态与页面行为

分别显示任务状态、入口/落地心跳状态、订阅发布资格。离线不自动等于服务已停止；移除成功不等于卸载；失败或取消不声称远端监听已经消失。

进入节点页、点击刷新以及节点页可见且无模态窗口时每 30 秒刷新。支持按名称、服务器、入口、落地搜索，以及可加入/暂不加入订阅筛选。并发请求只展示最新响应；读取失败清空旧操作列表并显示重试提示，不把旧结果当作当前状态。

## 7. Job 与管理操作

不新增 Job。直连卡片进入“管理部署”，链路卡片进入“管理链路”；查看任务和入口详情沿用原接口。托管卡片没有普通编辑、删除、批量勾选或排序控件，防止误导用户修改派生连接字段。

手工保存只提交手工节点，避免另一会话更新托管配置后旧页面提交过期托管快照。服务器已有的托管归属保护保持有效；手工批量删除及排序不会改变部署记录。

## 8. 测试

Python 覆盖所有管理状态、依赖提示、超时自动处理、撤销后发布资格、响应脱敏、缺少密钥仍可读取和管理员权限。Node 覆盖筛选、状态语义与管理目标选择。

浏览器临时样本覆盖 pending/failed/removed、两个归属配置入口、筛选、恶意名称按文本展示、无托管勾选/删除按钮、其他会话改变发布状态后的手工节点排序保存，以及清单请求失败恢复。完整 Python/Node 回归及 Ruff/privacy/syntax 检查同时运行。

## 9. 安全措施

托管名称和服务器信息使用 DOM textContent 显示，不拼接为可执行 HTML 或 inline handler。点击操作使用闭包保存的 Agent ID；重新读取 Agent 后仍受管理 API 鉴权。新清单不接触凭据解密、运行服务、SSH、命令、路径或防火墙。

## 10. 未实现内容

此阶段不新增批量部署、跨机器事务、持续公网健康探测、凭据轮换或远程卸载。单入口一条附加链路等 B5b 限制仍适用。控制台撤销和删除记录不代表停止远端监听。

## 11. 升级

只需升级 Controller 后端和完整 static 目录；无需 Agent 升级或数据库迁移。若使用缓存代理，应确保前端脚本与后端 API 来自同一版本。

## 12. 回滚

恢复 B5b 的 Controller 与 static 即可，schema 保持 5；部署、链路、任务和客户端凭据不变。B5a 及更早版本仍需遵循已有数据库降级要求。MEMORY.md 继续本地忽略，不进入镜像或上传 VPS。
