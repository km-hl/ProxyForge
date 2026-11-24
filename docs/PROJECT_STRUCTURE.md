# 项目结构与开发边界

## 1. 目录结构

```text
ProxyForge/
├── main.py                    # FastAPI 入口、路由装配、生命周期与后台巡检
├── proxyforge/                # Controller 服务端包
│   ├── airports/              # 上游机场解析、并发拉取、原子缓存与后台刷新
│   ├── config/                # 模板事务与修订历史、DNS/TUN 校验、Mihomo 基线
│   ├── control/               # Agent 注册/心跳、Job 租约、多节点部署、接管资产、go-gost 编排与 SQLite 存储
│   ├── nodes/                 # 手工节点管理与订阅节点全局混排顺序
│   ├── security/              # 管理凭据/会话、登录限速、安全出站（DNS Pinning / 预算）
│   ├── subscription/          # 订阅总装、多用户配额与极简分流、Mihomo/Sing-box/Surge/Egern/URI 导出
│   └── templates/             # 模板保存、历史恢复与全局导入 Router
├── agent/                     # 独立节点守护程序（仅依赖 Python 3.9+ 标准库）
├── static/                    # 原生 ES Module 前端（无构建步骤，修改即生效）
├── scripts/                   # CI 校验、依赖锁定、容器迁移与固定包工具
├── tests/                     # Python 单元/集成测试、Node.js 前端测试与 Mihomo 兼容样例
├── docs/                      # 部署、安全、导出与架构文档
├── data/                      # 运行数据目录（Git / Docker 忽略）
├── Dockerfile / docker-compose.yml / proxyforge.service
└── requirements*.in / requirements*.txt
```

根目录中 `MEMORY.md`、`PLAN.md`、`TODO.md`、`AGENTS.md` 与 `.env` 仅限本机使用，已被 `.gitignore`、`.dockerignore` 与隐私脚本禁止提交或打包。

## 2. 核心模块职责

### Controller (`proxyforge/`)

| 模块 | 职责 |
| --- | --- |
| `airports/api.py`, `service.py`, `sources.py`, `parser.py` | 机场管理接口、统一单实例 `AirportService`（12h 节点缓存 / 24h 元信息缓存、来源代次失效、每批 5 并发与 180s 预算）及 YAML/Base64/URI 解析 |
| `config/template_store.py`, `network_config.py`, `mihomo_compat.py` | 文件锁、原子提交、事务恢复、乐观锁 `expected_revision` 与模板历史；基于 Mihomo v1.19.31 的 DNS/TUN 校验基线 |
| `control/control_store.py`, `job_store.py` | SQLite 存储（当前 `CURRENT_SCHEMA = 8` 并在 `_ensure_stage_extensions` 幂等维护扩展表）、Agent 注册/心跳/撤销与 Job 租约队列 |
| `control/deployment_store.py`, `deployment_api.py`, `chain_store.py`, `gost_store.py`, `gost_api.py`, `managed_inventory.py`, `agent_api.py`, `agent_installation.py` | Fernet 加密存储期望配置、单机多节点部署与同端口复用同步、`CLIENT_METADATA_ONLY_FIELDS` 零重启热改、接管资产、go-gost 转发/链/Best-Exit 与 `rewrite_subscription`、`/api/agent/install.sh` 与 `package.tar.gz` 托管 |
| `nodes/api.py`, `ordering.py` | 分享链接解析、手工节点 CRUD（保护托管只读节点）及 `data/node_order.json` 全局排序 |
| `security/runtime_security.py`, `api.py`, `network_security.py`, `outbound_budget.py`, `auth_rate_limit.py` | 管理/订阅凭据分离、HttpOnly 会话、登录限速、独立 Session + DNS Pinning + 显式 CA + 出站预算 |
| `subscription/api.py`, `builder.py`, `minimal_profile.py`, `users.py`, `nodes.py`, `links.py`, `validation.py`, `singbox.py`, `surge.py`, `egern.py` | 主订阅与 `/sub/{user_token}` 多用户 UA 自适应订阅、确定性每用户每节点凭据派生、`subuser:<mark_id>` 内核态流量核算与 60s 后台巡检、五端导出（含 `GEOSITE`/`GEOIP`/`DOMAIN-REGEX` 与 `,no-resolve`）及国旗/中转重写 |
| `templates/api.py` | 模板读取、校验、保存、历史恢复与原子全局导入 |

### Agent (`agent/`)

- **核心进程与通信**：`main.py`、`client.py`（严格 `ALLOWED_ENDPOINTS` 白名单）、`jobs.py`、`job_lease.py`、`system_info.py`（公网 IPv4/IPv6、`bundle_sha256`、`self_upgrade_protocol_version`、`nftables_capable` 上报）。
- **多服务运行时与特权隔离**：`runtime_helper.py`（root Unix Socket `proxyforge-runtime.socket` 隔离特权操作）、`runtime_engine.py`（`RuntimeCoordinator`、跨服务端口冲突校验、配置字节未变跳过重启）、`runtime_download.py`（固定 SHA256 下载与 root 持久化 `gh-proxy` 镜像）、`runtime_spec.py`、`self_upgrade.py`（心跳感知 `latest_bundle_sha256`、SHA256 校验与按需平滑重启）。
- **协议与数据面**：`landing_spec.py`（五大抗封锁协议、同端口 `auth_user` 合并、`outbound_mode: chain` 1–4 跳 `detour`、多用户 `routing_mark = 0x50460000 | mark_id` 与 `no_user_marks` 降级）、`acme_manager.py`（HTTP-01 / DNS-01）、`caddy_manager.py`（三模伪装站，禁用 HTTP/3 免占 UDP 443）、`adoption.py`（宿主机 `sing-box` / `xray` 扫描接管归还）、`gost_manager.py`（`go-gost` 转发/链/Best-Exit）、`nft_users.py`（`table inet proxyforge_users` 用户字节计数器）、`traffic_collector.py`（Prometheus + `nftables` 多 epoch 防重启回退增量上报）。

### 前端 (`static/`)

原生 ES Module 控制台（Dub.co 浅色中性风，严禁堆砌静态科普小字）：

- `index.html`、`style.css`、`app.js`：统一侧边栏/移动端抽屉、全局弹窗底栏 (`openModal` / `setModalFooter`)、规则与模板编辑、统一节点排序与地区选择器。
- `agents.js`：服务器卡片、一键安装与引导升级、五协议部署（含同端口复用锁定）、转发与存量接管 UI。
- `sub-users.js`：独立「多用户订阅」面板、配额进度与按服务器分组可视化节点选择器。
- 工具模块：`icons.js`、`html-utils.js`（XSS 转义）、`rule-utils.js`、`share-link-utils.js`、`node-order-utils.js`、`subscription-utils.js`（含纯 JS SVG 二维码）、`network-settings.js`、`template-session.js`、`template-history.js`、`managed-nodes.js`。

## 3. 依赖边界与工程不变量

```text
main.py → airports / nodes / templates / control / config / security / subscription
control → agent/*_spec.py + security
agent   → 仅 Python 3.9+ 标准库及 agent 内部模块（严禁反向导入 proxyforge.*）
```

- **单进程边界**：Controller 为单进程单副本运行（不启多 worker 共享同一 `data/` 目录）。
- **包隔离**：`proxyforge` 子包不得反向导入 `main.py`；`agent/` 不得依赖任何第三方包或 `proxyforge.*`（由 `tests/test_package_boundaries.py` 与 CI `python -S` 矩阵强制校验）。
- **日志与隐私**：服务端错误/校验日志仅记录固定提示与异常类型/数量，禁止输出订阅 URL、Token、私钥、PSK、DNS Secret 或代理密码；前端所有 `innerHTML` 动态字段必须经 `html-utils.js` 转义。
- **数据面隔离**：所有 L4/L7 转发与流量计数由托管 `sing-box` / `go-gost` / `nftables` 执行，Python 仅做控制面编排与增量入库。

## 4. 本地验证命令

```bash
# 后端与 Agent 全量测试
python -m unittest discover -s tests -v

# Agent 纯标准库隔离校验（无需第三方包）
python -S -m compileall -q agent
python -S -m unittest discover -s tests -p test_nft_users.py -v
python -S -m unittest discover -s tests -p test_agent_self_upgrade.py -v

# 前端语法与全量测试
node --test tests/*.test.js

# 静态检查、依赖锁与隐私边界
ruff check --select E9,F63,F7,F82 .
python -m compileall -q main.py proxyforge agent scripts
python scripts/check_dependency_locks.py
python scripts/check_repository_privacy.py
git diff --check
```

依赖锁更新流程见 [依赖锁说明](DEPENDENCIES.md)，容器权限与非 root 演练见 [容器权限说明](CONTAINER_PERMISSIONS.md)，出站安全见 [机场出站 HTTP 说明](OUTBOUND_HTTP.md)。
