# 项目结构与开发边界

## 1. 文件结构

```text
ProxyForge/
├── main.py                    # Web 入口、API 编排、运行文件与机场缓存
├── proxyforge/                # Controller 内部 Python 包
│   ├── control/               # Agent/Job/Deployment/Chain API 与 SQLite 存储
│   ├── config/                # 模板事务与历史、DNS/TUN 校验、Mihomo 基线
│   ├── security/              # 管理凭据/会话、登录限速、安全出站请求
│   └── subscription/          # 纯函数：分享链接、节点投影、校验与生成
├── agent/                     # 独立 Agent、协议规格、runtime helper 与安装资源
├── static/                    # 浏览器 HTML/CSS/JS，既有 URL 保持兼容
├── scripts/                   # 开发/CI 工具；不在生产请求中执行
├── tests/                     # Python/Node 测试、合成 fixtures、真实 Mihomo 用例
├── docs/                      # 架构、各阶段报告及发布恢复流程
├── data/                      # 私有运行数据；不跟踪、不进入镜像
├── .local/                    # 本地临时验证产物；不跟踪、不进入镜像
├── .github/workflows/ci.yml   # 自动化检查与真实内核运行测试
├── Dockerfile
├── docker-compose.yml
├── proxyforge.service
├── requirements.txt
├── requirements-dev.txt
├── template.example.yaml
└── custom_nodes.example.yaml
```

根目录保留启动、部署、依赖和初始化样例。`MEMORY.md` 仅作本机记忆，Git/Docker 忽略，永不上传 VPS。

## 2. Controller 模块与数据模型

| 位置 | 职责 |
| --- | --- |
| `control/agent_api.py`、`job_api.py`、`deployment_api.py` | 管理/Agent 路由、鉴权衔接、请求与响应 schema |
| `control/control_store.py` | SQLite 连接、migration、注册、身份和心跳 |
| `control/job_store.py` | 租约、重试、状态回报与任务保留 |
| `control/deployment_store.py`、`chain_store.py` | 加密期望配置、版本冲突、依赖和节点发布条件 |
| `control/managed_inventory.py` | 不读取秘密的节点管理清单 |
| `config/template_store.py` | 文件锁、原子提交、事务恢复和模板历史 |
| `config/network_config.py`、`mihomo_compat.py` | DNS/TUN 纯校验与固定兼容基线 |
| `security/runtime_security.py` | 持久化凭据、管理密钥验证与会话 |
| `security/network_security.py`、`auth_rate_limit.py` | 出站请求限制及登录限速 |
| `subscription/links.py` | 分享链接解析 |
| `subscription/nodes.py` | 来源命名、国旗名称、内部字段剥离及节点投影 |
| `subscription/validation.py` | 节点与完整 Mihomo 配置校验 |
| `subscription/builder.py` | 由显式输入构建订阅/provider，清理生成结果中的引用 |

表中路径相对于 `proxyforge/`。数据库仍为 schema 5；运行文件仍使用 `data/`，没有存储格式变化。

## 3. API 与启动入口

保持 `uvicorn main:app`、`python main.py`、Docker Compose 与原 systemd 入口。`main.py` 继续负责 Web 路由编排、运行数据初始化和机场请求/缓存；导入此入口仍有初始化副作用，测试应使用现有隔离加载器。

`proxyforge` 包的 `__init__.py` 不装配应用；导入内部库不创建运行数据，不加载 `.env`。HTTP 路径、请求模型、静态资源 URL 和订阅输出保持原有行为。

Controller 当前支持单进程、单副本运行，不启用多个 Uvicorn worker 或共享数据目录的多个 Controller。机场缓存的线程协调、来源失效与部署边界见[机场缓存并发说明](AIRPORT_CACHE_CONCURRENCY.md)及[后台刷新生命周期](AIRPORT_BACKGROUND.md)。

机场请求的 Session 隔离、显式 CA 配置及尚待实现的 DNS pinning 边界见[机场 HTTP 请求说明](OUTBOUND_HTTP.md)。

## 4. 鉴权与模块依赖

```text
main.py → control / config / security / subscription
subscription.builder → subscription.validation / nodes
subscription.validation → config.network_config
control → agent 协议规格 + security
agent → 标准库及自身模块（不依赖 Controller 包）
```

控制面与订阅算法不能反向导入 `main.py`。纯订阅模块只能使用显式参数；文件、网络和请求鉴权仍由入口及对应存储/安全模块负责。管理身份、Agent 凭据和订阅 token 的边界保持原样。

## 5. Agent 协议与分发

Agent 保持独立目录和 `python -m agent.main` 入口。安装脚本的文件清单、root helper、能力标记和协议规格不移动；Controller 仍引用 `agent/*_spec.py` 共享严格规格。Agent 版本仍为 0.6.0。

## 6. 状态机

本次只移动模块及导入位置，不改变模板冲突、Job 租约、Deployment/Chain 版本、失败回滚或节点发布状态。`main.py` 中的生成/校验名称仍从纯模块导入，供入口编排和已有生成工具使用。

## 7. Job schema 与内部导入

无新任务、payload 或远程动作。原根目录内部模块导入改为完整包路径，例如：

```python
from proxyforge.control.control_store import ControlStore
from proxyforge.security.runtime_security import RuntimeConfigStore
from proxyforge.subscription.builder import build_subscription_config
```

维护自定义 Python 运维脚本时同步修改旧的根模块导入；HTTP、CLI 和 Agent 操作方式不变。不保留同名根目录转发文件，以免出现两份模块状态或继续依赖旧目录。

## 8. 测试与开发

分享链接和配置生成测试现在直接导入生产使用的纯模块，不再从 `main.py` 抽取 AST 后复制执行。真实生成测试仍验证构建前后两道校验；新增全新进程的库导入检查和 Agent 独立依赖检查。

在仓库根目录运行：

```bash
python -m unittest discover -s tests -v
node --test tests/rule_order.test.js tests/html_security.test.js tests/network_settings.test.js tests/template_session.test.js tests/agents.test.js tests/managed_nodes.test.js
ruff check --select E9,F63,F7,F82 .
python -m compileall -q main.py proxyforge agent scripts
python scripts/check_repository_privacy.py
```

CI 编译范围覆盖完整包；Mihomo 生成与 sing-box/systemd 工具同步使用新导入。保留测试目录和 fixture 相对路径，延续现有 unittest discovery 与 Node 测试入口。

## 9. 安全与隐私

分享链接解析和订阅生成不读取运行数据，不联网，不执行 shell。移动不降低验证门禁。构建仍使用 Docker 忽略规则排除私有数据、本地脚本和记忆；运维备份与隔离演练遵循[发布流程](RELEASE_ACCEPTANCE.md)。

## 10. 整理范围

本次不重写 UI、不引入前端构建链，不迁移运行数据。`main.py` 保留与文件状态和请求上下文相关的编排；后续若继续拆分路由，应显式注入存储依赖并覆盖事务/缓存行为，不能只为缩短文件而产生循环依赖。

## 11. 升级

升级完整 Controller checkout/镜像；不能只拷贝新的 `main.py` 而漏掉 `proxyforge/`。无需数据库 migration、凭据变更或 Agent 升级。先用生产冷备副本验收导入、订阅及管理接口，再切换服务。

## 12. 回滚

回退到整理前的完整 Controller 镜像/代码，schema 和数据格式兼容；不得混用新入口与旧根模块。数据恢复仅在确实发生数据问题时按发布流程进行，不因目录回退而覆盖用户的新配置。
