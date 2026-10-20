# 项目结构与开发边界

## 1. 文件结构

```text
ProxyForge/
├── main.py                    # Web 入口、API 编排、运行初始化与服务装配
├── proxyforge/                # Controller 内部 Python 包
│   ├── airports/              # 机场解析、拉取、缓存与刷新协调
│   ├── nodes/                 # 节点管理 Router，显式复用存储和只读边界
│   ├── templates/             # 模板管理 Router，显式复用版本校验和配置事务
│   ├── control/               # Agent/Job/Deployment/Chain API 与 SQLite 存储
│   ├── config/                # 模板事务与历史、DNS/TUN 校验、Mihomo 基线
│   ├── security/              # 管理凭据/会话、登录限速、安全出站请求
│   └── subscription/          # 公开订阅 Router 与分享链接、节点投影、校验和生成
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
| `nodes/api.py` | 分享链接解析、节点读写与代理聚合的管理 Router |
| `templates/api.py` | 模板校验、保存、历史、恢复与全局导入的管理 Router |
| `airports/api.py` | 三个机场管理接口的 Router 工厂、旧请求模型及共享 URL 校验 |
| `airports/service.py` | 显式注入依赖，统一机场节点/元信息缓存与后台刷新协调 |
| `airports/sources.py` | AirportSource / AirportSnapshot 内部快照，旧格式投影与来源身份比较 |
| `airports/parser.py` | 纯 YAML / Base64 订阅解析，格式失败回退，其他故障与控制信号向外传播 |
| `control/agent_api.py`、`job_api.py`、`deployment_api.py` | 管理/Agent 路由、鉴权衔接、请求与响应 schema |
| `control/control_store.py` | SQLite 连接、migration、注册、身份和心跳 |
| `control/job_store.py` | 租约、重试、状态回报与任务保留 |
| `control/deployment_store.py`、`chain_store.py` | 加密期望配置、版本冲突、依赖和节点发布条件 |
| `control/managed_inventory.py` | 不读取秘密的节点管理清单 |
| `config/template_store.py` | 文件锁、原子提交、事务恢复和模板历史 |
| `config/network_config.py`、`mihomo_compat.py` | DNS/TUN 纯校验与固定兼容基线 |
| `security/runtime_security.py` | 持久化凭据、管理密钥验证与会话 |
| `security/api.py` | 登录/状态/退出与订阅密钥、管理密钥设置的管理 Router |
| `security/network_security.py`、`auth_rate_limit.py` | 出站请求限制及登录限速 |
| `subscription/api.py` | 默认/Egern 订阅、机场 provider 和 Egern 规则资源的公开 Router |
| `subscription/links.py` | 分享链接解析，格式/字段失败返回 None，其他故障与控制信号向外传播 |
| `subscription/nodes.py` | 来源命名、国旗名称、内部字段剥离及节点投影 |
| `subscription/validation.py` | 节点与完整 Mihomo 配置校验 |
| `subscription/builder.py` | 由显式输入构建订阅/provider，清理生成结果中的引用 |

表中路径相对于 `proxyforge/`。数据库仍为 schema 5；运行文件仍使用 `data/`，没有存储格式变化。

## 3. API 与启动入口

保持 `uvicorn main:app`、`python main.py`、Docker Compose 与原 systemd 入口。`main.py` 继续负责 Web 路由编排、运行数据初始化和 AirportService 装配；机场请求与缓存协调位于 `proxyforge/airports/`。导入此入口仍有初始化副作用，测试应使用现有隔离加载器。

`proxyforge` 包的 `__init__.py` 不装配应用；导入内部库不创建运行数据，不加载 `.env`。HTTP 路径、请求模型、静态资源 URL 和订阅输出保持原有行为。

Controller 当前支持单进程、单副本运行，不启用多个 Uvicorn worker 或共享数据目录的多个 Controller。机场缓存的线程协调、来源失效与部署边界见[机场缓存并发说明](AIRPORT_CACHE_CONCURRENCY.md)及[后台刷新生命周期](AIRPORT_BACKGROUND.md)。

机场请求的 Session 隔离、DNS pinning 与显式 CA 配置见[机场 HTTP 请求说明](OUTBOUND_HTTP.md)；`security/outbound_budget.py` 管理单次截止时间、socket 中断和有界 DNS 等待，批次准入与退出边界见[出站时间预算](OUTBOUND_BUDGETS.md)。

`GET /sub` 的通用异常仍返回原 500 中文纯文本响应；应用错误日志只记录固定提示“订阅生成失败”和异常类型，不格式化异常对象、不记录原始消息或 traceback。该边界覆盖构建、YAML 读取、Egern 转换及最终序列化，保留 `ConfigValidationError` 的 422/警告级别与 `HTTPException` 的原响应；退出/取消信号继续向外传播。此前通用错误日志批次不包含校验详情日志，后续独立处理见下文；HTTP 访问日志由入口另行控制。`tests/test_subscription_error_logs.py` 以临时目录、合成异常与实际 YAML 错误验证日志、响应、控制信号和两种正常导出，测试不请求真实上游。

配置辅助函数的五处异常日志也仅记录固定提示及异常类型：模板初始化、自建节点迁移、机场列表读取、手动节点读取和模板引用清理。日志脱敏批次保留了当时的捕获范围；文件读取的后续预期异常类别见下文。格式/文件错误仍返回空列表，迁移失败仍返回空路径，YAML 清理失败仍返回空引用结果；不重写损坏文件，不新增网络请求。`tests/test_config_error_logs.py` 直接验证真实文件与默认/Egern 订阅调用链，保证这些错误日志不回显异常消息或片段。初始化成功路径提示和 HTTP 访问日志不在上述五处辅助错误日志范围；订阅校验警告另见下文。

### 订阅校验警告

订阅 `ConfigValidationError` 的 WARNING 只记录固定描述和错误数量，例如“订阅配置校验失败（3 项错误）”，不再拼接校验错误正文。节点名称、错误端口、协议字段或规则内容可能含私有数据，不能把给请求方的诊断直接复制进服务端日志。HTTP 422 中文纯文本及逐项详情保持原样，供已授权订阅持有者排查；默认/Egern 和 provider 校验共用此边界。`tests/test_subscription_validation_logs.py` 覆盖真实手动/机场节点错误、多个/provider 校验错误与正常导出，只改日志内容，不改级别、状态、响应、文件或其他错误处理。

## 4. 鉴权与模块依赖

```text
main.py → airports.api / airports.service / nodes.api / templates.api / control / config / security / subscription
security.api → FastAPI / Pydantic + 入口注入的鉴权、存储、限速和会话回调
nodes.api → config.template_store / subscription.links / nodes / validation / builder
templates.api → airports.service / config.network_config / template_store / subscription.nodes / validation
airports.api → airports.service / config.template_store / security.network_security / subscription.builder / nodes
airports.service → airports.sources / airports.parser / config.template_store / security.outbound_budget
airports.sources → subscription.nodes
airports.parser → subscription.links
subscription.builder → subscription.validation / nodes
subscription.api → subscription.builder / nodes / validation + FastAPI
subscription.validation → config.network_config
control → agent 协议规格 + security
agent → 标准库及自身模块（不依赖 Controller 包）
```

控制面与订阅算法不能反向导入 `main.py`。纯订阅算法模块只能使用显式参数；公开 Router 通过显式回调复用文件、网络、运行密钥和资源函数，不创建它们的副本。管理身份、Agent 凭据和订阅 token 的边界保持原样。

### 管理鉴权 Router

`security.api.create_security_router` 返回 `SecurityApi(router, auth_login, auth_status, auth_logout, get_config, update_config, update_admin_token)`；六个原接口为 `POST/GET /api/auth`、`POST /api/logout`、`GET/POST /api/config` 和 `POST /api/admin-token`。`ConfigModel`、`AdminTokenModel` 定义迁入该模块，入口保留同一模型和实际处理函数绑定。只有首页静态文件响应、中间件、应用异常处理器和启动/停止装配继续直接位于入口，各业务 API 归属对应 Router。

九项依赖为 `verify_management`、`store_reader`、`limiter_reader`、`session_writer`、`cookie_name_reader`、`subscription_token_reader`、`subscription_token_writer`、`admin_minimum_reader`、`insecure_tokens_reader`。入口的管理鉴权、同源判断和 Cookie 写入辅助函数未迁移或改写，继续被所有管理 Router 共享。工厂装配不读取/创建运行配置、会话或限速器；运行时读取同一存储和限速状态，保留按客户端来源限速与 429/Retry-After。

订阅密钥仍先完成持久化，再经入口 `_apply_subscription_token` 更新实时全局值，公开三个接口的 token 回调立即读取新值；失败不得提前切换。管理密钥轮换仍由原存储撤销旧会话，再写入新会话 Cookie。退出接口保留原来的 Cookie 删除行为，不额外改变服务端会话撤销语义。原管理/订阅身份隔离、Cookie 写操作同源校验、Bearer 行为、400/401/403/422/429 与存储失败响应均保持。`tests/test_security_router.py` 覆盖隔离装配、动态依赖、持久化/切换顺序、会话轮换与真实公开接口的密钥生效；该结构批次不变更鉴权协议或新增 schema。

### 公开订阅 Router

`subscription.api.create_subscription_router` 返回 `SubscriptionApi`，包含 router 与三个实际处理函数：`get_egern_rule_set`、`get_airport_provider`、`get_subscription`。入口只挂载一次并将同名 Python 名称绑定到这些函数；`GET /egern/ruleset/{kind}`、`GET /provider/{airport_index}`、`GET /sub` 的 Query、operationId、状态、响应头和正文保持一致。

十五项依赖显式注入：`token_reader`、`template_reader`、`sources_reader`、`nodes_reader`、`managed_names_reader`、`references_cleaner`、`subscription_reader`、`airport_service`、`service_errors`、`rule_loader`、`config_builder`、`provider_resolver`、`egern_builder`、`ca_bundle_reader`、`logger`。密钥和 CA 逐请求回调读取，不能在装配时捕获旧字符串。回调动态引用入口的当前工具与路径，工厂不读取配置、创建机场服务或持有第二份缓存，也不导入/重载 Egern 资源模块。

保留 `Request.base_url` 和 root_path 构造链接、Unicode 订阅头、默认/Egern 分支、机场顺序和 provider 索引、缓存回退的来源名称匹配、内部字段剥离及导出前引用清理。复用同一 AirportService 与原错误适配器；规则资源继续使用原有缓存、并发槽位、DNS pinning 和预算。三个接口只接受实时订阅密钥，不接受管理身份；不能给它们附加管理 Cookie 同源校验。既有 400/401/404/422/500/502/503 响应和退出/取消信号边界不在结构迁移中修改。`tests/test_subscription_router.py` 验证隔离、动态依赖和原错误/导出契约，已有真实生成与日志回归继续覆盖实际装配。

### AirportService 装配约定

每个 Controller 进程只装配一个 `airport_service`，管理来源保存/全局导入、订阅、provider、元信息和后台刷新均使用该实例。服务持有节点 TTL 缓存、RLock、来源代次/快照、元信息代次和请求接受序号；不能为各请求另建实例。

构造参数 `sources_reader`、`cache_path`、`info_cache_path`、`http_get`、`clock`、`monotonic`、`configuration_lock` 均由入口显式传入；另可传 `ca_bundle`、`batch_timeout` 和 logger。入口在当前数据目录中固定两个缓存的绝对路径；服务不读取 `.env` 或创建目录。`clock` 为 Unix 时间，`monotonic` 须与 `safe_get` 的 `time.monotonic()` 使用同一时间域；前者用于 JSON 缓存，后者用于 TTL 与批次期限。不得混用两种时间。

`configuration_lock` 是可重入的上下文管理器工厂，入口传 `TemplateStore.locked()`，先完成提交恢复再读取来源。固定配置锁→缓存锁顺序，联网不持锁；来源回调仍返回旧 URL 字符串、对象及未知扩展字段，服务只在内存中建立类型，不重写磁盘。旧环境迁移/管理提交、鉴权、HTTP 状态和异步生命周期仍由入口负责。

核心接口为 `airport_cache_snapshot()`、`airport_cache_locked(snapshot)`、`get_airport_proxies_cached(snapshot=None)`、`subscription_airports()`、`get_airports_info(force_indices="")`、`refresh_airport_cache(stop_event=None)` 和 `invalidate_airport_cache(clear_disk=False)`。服务抛出 `AirportSourcesChanged` / 存储 `OSError`，入口在不持锁的错误适配器中沿用原 503 与存储错误响应；校验错误仍沿用订阅的 422。`main.py` 的节点缓存/订阅/后台刷新函数仅作适配，不持第二份状态。

内部 `airport_cache_snapshot()` 现在返回 `AirportSnapshot(sources, generation)`，`sources` 是保持原顺序的 `AirportSource` 元组。Python 调用方使用 `snapshot.sources`、`snapshot.generation`，需要旧格式列表时调用 `snapshot.to_legacy()`，不要继续使用旧二元 tuple 的数字下标。`save_cache_to_file` 和 `airport_cache_locked` 接收该快照；`subscription_airports()` 对入口/订阅构建器继续返回旧格式列表及节点。

`AirportSource.from_legacy(value, index)` 支持旧 URL 字符串和对象，保存完整原始值的深拷贝；`to_legacy()` 返回新的副本。`url` 为节点请求使用的去空白字符串，非法类型/空值返回 `None`，不将数值或布尔值转成 URL；`name` 沿用节点命名。`info_url` / `info_alias` 保留元信息旧规则：别名不 trim、不收紧类型，空白别名、同 URL 多别名及 content-disposition 名称回退与节点命名分开处理。安全 URL 校验仍由原 API 与实际 HTTP client 执行。

模型只读字段和对外深拷贝防止修改响应污染来源快照；原始 URL、嵌套扩展字段均参与来源比较，不能用规范化后的 URL 判定同一配置。未知字段变更、来源重排、原始空白差异与来源代次仍受原失效规则保护。模型 `repr` 不输出原始 URL/扩展字段；不要将包含原始来源的导出副本用于诊断日志。API 的 `List[Any]`、400/422、YAML 注释与格式均保持兼容；不把内部 dataclass 用作外部请求/响应 schema。

### 机场拉取日志的来源标识

`fetch_airport_item` 的开始、成功、空节点和失败四类日志只使用来源的从 1 开始位置，不记录原始别名或主机名；别名本身也可能包含 URL、token、节点凭据或换行。失败仍只记录异常类型，不格式化异常或附带 traceback。日志位置与配置列表顺序对应，来源重排后不保证是同一身份；Python 内部调用传入非正常位置时以 `#0` 表示未知位置，不格式化该值。

该修改只影响日志。节点 `_airport_name`、配置/API 显示名、元信息别名、缓存匹配与请求 URL 均保留原值；原字符串来源、命名对象、空结果/逐来源错误隔离与退出信号也不变。`tests/test_airport_log_identities.py` 用合成敏感别名验证正常、空节点、错误与异常位置分支，测试不请求真实上游。

YAML 节点缓存、JSON 元信息缓存、12 小时/24 小时 TTL、两次快照尝试、5 个并发请求和 180 秒批次预算保持兼容。`tests/test_airport_service.py` 直接装配独立服务验证依赖、实例隔离、旧来源扩展字段、时钟、解析及错误边界；原有并发/原子写/预算/生命周期测试继续覆盖实际生产服务，HTTP 测试保留鉴权、provider 和默认/Egern 订阅。

节点磁盘缓存读取捕获文件、Unicode 解码、YAML 解析/标量构造及过深嵌套的预期异常，日志只记固定描述及错误类型，返回空列表且不重写损坏文件。其余错误在此函数内不吞掉，配置锁/事务恢复失败仍由存储适配器处理；详见[读取异常与回退边界](AIRPORT_CACHE_CONCURRENCY.md#验证与边界)。这是第 11 项的独立兼容修复，不改变来源代次、缓存格式或正常订阅行为。

订阅解析的五处裸 `except` 已独立收窄至 `except Exception`：机场 YAML/Base64 两层，以及分享链接 VMess、SS、其他协议三个分支。`KeyboardInterrupt`、`SystemExit`、`asyncio.CancelledError`、`GeneratorExit` 在直接解析、嵌套订阅和机场拉取线程池内实际抛出时向外传播，不转换为 `None`、空列表、部分节点或机场元信息错误。普通解析异常继续沿用原回退：先 YAML、后 Base64，普通无效分享链接仍跳过。`tests/test_parser_cancellation.py` 使用合成数据和模拟 HTTP 覆盖这些边界；按具体格式进一步收窄的本批边界见下节，仍待独立审查合并。现有停止事件、出站预算和后台线程关闭管理保持原契约，此修复不负责终止正在运行的线程。

### 机场管理 Router 试点

`airports/api.py:create_airport_router()` 在应用装配时建立三个管理路由：`GET /api/airports`、`POST /api/airports`、`GET /api/airports/info`。模块导入不创建 app、读取环境或运行文件；只有显式装配才创建 Router，装配本身也不读取配置或启动网络工作。

入口注入 `verify_management`、`configuration_lock`、`sources_reader`、`template_reader`、`template_store`、`airport_service` 和 `service_errors`。它们分别复用原管理鉴权、可恢复配置锁、旧格式读取回调、模板读取/提交工厂、单一机场服务与不持锁的 HTTP 错误适配器。不得为 Router 新建第二个 AirportService 或另配一套提交锁。

工厂返回 `AirportApi`，其中有 `router` 及 `get_airports` / `update_airports` / `get_airports_info` 三个实际处理函数；`main.py` 只 include 一次 Router，并把原 Python 名称直接绑定到这些函数，不再注册同路径路由或实现第二份处理逻辑。`AirportsModel` 和 `check_airport_urls` 在 API 模块定义，入口保留导入名称供内部工具使用；全局导入继续共用同一个 URL 校验函数。

路径、请求/响应字段、operationId、管理与订阅身份边界、Cookie 同源校验和安全响应头保持兼容。机场保存仍在同一配置锁内校验 URL、清理移除的 provider 引用、失效缓存，再用 TemplateStore 一次提交来源/模板；409/413 交由应用原异常处理器，存储故障和元信息来源冲突沿用原 503。元信息网络工作保持不持配置锁。

机场管理首先迁移三个接口，节点和模板管理随后独立提取，见下节。公开 `/provider/{airport_index}`、默认/Egern 订阅及 auth 路由继续由入口编排；后续按依赖评估逐批迁移，不一次搬动全部路由。`tests/test_airport_router.py` 覆盖依赖隔离、单一处理函数绑定、鉴权/同源和共享错误处理；原有事务、源代次、后台退出与模板恢复测试继续覆盖真实生产路径。

### 纯解析异常边界

`parse_airport_response` 的 YAML 阶段只将 `YAMLError`、`ValueError`、`TypeError`、`AttributeError`、`KeyError`、`IndexError`、`RecursionError` 作为格式/旧输入错误进入后续回退；包含 SafeLoader 非法日期、空整数/浮点、非法布尔/时间戳、深层嵌套及原非字符串输入的兼容行为；这些损坏标量并不都抛 YAMLError。Base64 解码阶段只捕获 `ValueError`、`TypeError`、`AttributeError`，保留无填充 Base64 与 UTF-8 失败回退；逐行分享链接解析位于解码 try 之外，其故障不得被误判为 Base64 损坏。

VMess 的 Base64/JSON/字段阶段保留 `ValueError`、`TypeError`、`AttributeError`、`OverflowError`、`RecursionError` 的 `None` 回退，覆盖非对象 JSON、非法端口/alterId、无穷数及过深 JSON。SS 与其余 URI 只捕获 `ValueError`、`TypeError`，包含 Base64/Unicode、URL/端口和协议字段错误。正常解析顺序、节点字段、普通无效行跳过行为不变；其他错误不再伪装成空结果，取消/退出信号仍向外传播，多行故障不返回部分节点或继续后续行。

纯函数不新增日志或 HTTP 策略，调用方继续使用既有逐来源、HTTP 和后台故障边界。机场逐来源仍可返回安全的空节点/元信息错误，不能因此断言底层解析器已经吞掉故障。`tests/test_parser_expected_errors.py` 覆盖真实格式错误与模拟运行故障，既有控制信号与各协议输出测试继续有效；入口文件读取的后续分类见下文。

### 配置与缓存读取异常边界

`load_airports`、`load_manual_nodes` 和 AirportService 的 `load_cache_from_file` 将 `OSError`、`ValueError`、`YAMLError`、`AttributeError`、`KeyError`、`IndexError`、`RecursionError` 作为文件/实际 YAML 数据错误，保留只读空列表回退和固定提示加类型的日志。空整数/浮点、非法布尔或时间戳并不都抛 YAMLError；其余 `RuntimeError`、`MemoryError`、`AssertionError`、`TypeError` 等读取故障继续向调用方报告，不能伪装为空配置。受锁恢复/来源身份与正常节点字段处理未改。

JSON 元信息缓存将解码深度 `RecursionError` 与原 `OSError`、`ValueError`、`UnicodeError` 一样回退为空对象、仅记错误类型，不覆盖损坏文件。JSON 解码深度阈值依 Python/平台不同，能够解析但条目结构无效的深层对象仍沿用固定结构警告。网络元信息/逐来源和后台的合理顶层故障隔离继续保留。`tests/test_config_reader_errors.py` 验证实际坏标量/深度、文件错误、非预期故障传播、无写盘和默认/Egern 订阅意外失败返回原 500；旧日志专项的 RuntimeError 空结果断言已随有意收窄改为新传播回归。

### 模板写入 YAML 的故障分类

`validate_saved_template` 在解析保存、全局导入和历史恢复内容时，只将 `YAMLError`、`ValueError`、`AttributeError`、`KeyError`、`IndexError`、`RecursionError` 视为实际 YAML 语法、标量或深度错误，保留原管理接口 400 详情。其余解析运行故障改为固定中文 500，应用日志只记固定提示及异常类型；不格式化异常、不附带 traceback，避免把程序/资源故障误报为用户格式错误。退出/取消信号继续传播，1 MiB 限制、正常内容与后续 Mihomo 语义校验不变；失败不提交模板、历史或导入配置。

`tests/test_template_yaml_errors.py` 验证真实坏标签/标量/深度、不可字符串化异常、运行/资源故障、三条实际管理写入路径及原文件/revision 不变。HTTP 500 是本次对非预期故障的明确分类变化，不能把旧行为中的 400 当作兼容承诺。已认证管理请求的实际 YAML 400 详情继续保留；这不授权将详情写入服务器日志。

保留的广义边界各有独立作用：后台任务防止永久退出、逐机场/元信息隔离来源故障、可选缓存序列化/写入失败保留原结果、公开订阅/provider/规则资源映射固定 HTTP 错误。安全 HTTP 的捕获仅在检查预算后重新抛出，数据库捕获用于回滚后重新抛出。这些边界不机械收窄，也不吞掉 `BaseException` 控制信号；应用入口访问日志另由既有禁用配置约束。本说明不代表任意外部 Python 启动方式、第三方日志或公网验收已经全面验证。

### 节点管理 Router

`nodes/api.py:create_node_router()` 显式装配四个管理接口：`POST /api/parse-links`、`GET /api/nodes`、`GET /api/proxies`、`POST /api/nodes`。导入及装配不创建全局 app、不读取文件/数据库或发起机场请求。`proxyforge/nodes/` 负责 HTTP 编排，`subscription/nodes.py` 继续只负责节点纯函数，两者职责不同。

工厂注入 `verify_management`、`configuration_lock`、`nodes_reader`、`airport_proxy_reader`、`manual_input`、`manual_nodes_reader`、`template_reader` 和 `template_store`。入口以回调复用现有组合节点读取、机场缓存读取、托管只读过滤、原始手动节点读取和同一个可恢复模板存储；不在 Router 内新建 ControlStore、AirportService、配置锁或维护另一份清单。

返回 `NodeApi(router, parse_links_api, get_nodes, get_all_proxies, update_nodes)`。入口只 include 一次，并把原四个 Python 名称直接绑定到实际处理函数；`NodesModel` 和 `ParseLinksModel` 在新 API 模块定义，入口保留导入名称。路径、请求/响应、operationId、模型校验与 400/401/403/409/422/503 保持兼容，管理鉴权与 Cookie 同源校验继续复用入口依赖。

GET 节点继续返回手动与可发布的托管节点，GET 代理继续按原顺序追加机场缓存节点。POST 节点仍先在配置锁内用 `manual_input` 跳过原样托管节点、拒绝其修改/伪装，然后校验手动节点、按原手动名称清理引用，再在一次 TemplateStore 提交中写入手动节点和必要的模板更新。托管数据库、成功发布条件和清单读取仍在原入口/控制面；空手动列表不能删除托管节点。节点解析只返回完整成功结果或原错误，不开始存储事务。

`tests/test_node_router.py` 验证独立装配/应用隔离、处理函数绑定、管理与 Cookie 边界、托管节点原样回传/禁止修改、失败不写盘、解析与存储独立，以及节点+模板提交中断后下一次读取同时恢复；既有部署/链路的真实 SQLite 只读节点回归、模板版本冲突和默认/Egern 订阅继续执行。整个第 9 项仍未完成，模板管理另见下节，后续继续评估订阅与鉴权路由的依赖。

### 模板管理 Router

`templates/api.py:create_template_router()` 装配七个管理接口：模板 `GET/POST /api/template`、`POST /api/template/validate`、`GET /api/template/history`、`GET /api/template/history/{entry_id}`、`POST /api/template/history/{entry_id}/restore` 和 `POST /api/template/import`。导入/装配无文件、数据库或网络操作，不创建全局 app、存储、锁或第二个机场服务。

入口显式注入以下依赖，读取/存储/校验回调动态引用当前入口配置：

| 边界 | 注入名称 |
| --- | --- |
| 管理身份与可恢复配置锁 | `verify_management`、`configuration_lock` |
| 模板存储、版本校验与保存 | `template_store`、`revision_required`、`template_writer` |
| 手动/组合/托管清单、托管名称与旧来源 | `manual_nodes_reader`、`nodes_reader`、`managed_nodes_reader`、`managed_names_reader`、`sources_reader` |
| 托管只读过滤、模板与来源校验 | `manual_input`、`validate_saved`、`validate_sources` |
| 共享缓存失效 | `airport_service` |

返回 `TemplateApi(router, get_template, validate_template, update_template, template_history, template_history_entry, restore_template, import_template)`。入口只 include 一次并绑定同一组实际处理函数；四个原请求模型 `TemplateModel`、`TemplateSaveModel`、`TemplateRestoreModel`、`ImportModel` 在新模块定义，入口保留导入名称。`require_revision`、`validate_saved_template`、模板初始化/读写、手动/托管清单等原工具入口保留，由回调复用；不反向导入 main 或复制库存。

模板读取、保存、恢复和全局导入继续持有原外层配置锁；保存/恢复/导入从版本检查、读取及校验直到提交均在同一把锁内，不能把 `expect` 和 `commit` 的单次方法锁当作完整比较并保存。全局导入继续先过滤托管节点、校验手动节点和来源/模板，再按完整旧来源值失效同一机场服务的缓存，通过一次 TemplateStore 提交模板、手动节点、机场来源三份文件。失效在提交前发生，提交故障后缓存可能已清除；持久事务中断仍由下一次受锁读取恢复，不拆成三个单文件写入。

路径、模型、operationId、正常响应与 400/401/403/404/409/413/422/428 等错误状态保持兼容。管理身份、四个 POST 的 Cookie 同源校验、应用级冲突/大小处理器与安全响应头保持；配置锁映射的存储故障仍 503，两项历史 GET 的直接存储故障仍沿用原 500。已有 YAML 错误正文等异常处理行为本批保留，后续按第 11 项独立修复，不混入结构搬迁。

`tests/test_template_router.py` 覆盖装配无 IO、两个应用隔离、实际处理函数/模型绑定、七接口管理鉴权、四个 POST 同源、校验/冲突无写、历史恢复、托管只读、来源扩展字段失效、三文件中断恢复和 Event 控制的并发保存。原模板跨进程 CAS、部署/链路 SQLite、机场并发及默认/Egern 回归继续执行。升级/回滚使用完整 Controller 代码或镜像并保留运行数据，无 schema、文件格式或 Agent/helper 变更；本批不包含生产部署。

## 5. Agent 协议与分发

Agent 保持独立目录和 `python -m agent.main` 入口。安装脚本的文件清单、root helper、能力标记和协议规格不移动；Controller 仍引用 `agent/*_spec.py` 共享严格规格。Agent 版本仍为 0.6.0。

`scripts/agent_artifacts.py` 只从完整提交的 Git 对象构建固定 Agent 包并校验，不安装服务；`agent/install-compatibility.json` 描述安装兼容基线，具体清单与信任边界见[安装产物契约](AGENT_ARTIFACTS.md)。中文操作入口为 `agent/README.zh-CN.md`。

`scripts/agent_bootstrap.py` 提供独立的固定源码下载、校验和 root 目录安装准备；`proxyforge/control/agent_installation.py` 提供无副作用的 URL 校验、固定版本元信息和命令生成，`scripts/agent_install_command.py` 作为文档 CLI 共用同一实现，见[完整安装指南](AGENT_INSTALL.md)。管理只读接口 `/api/agents/install-command` 读取部署配置并生成文本，不下载/执行代码；独立 `scripts/check_agent_installation.py` 只在专用一次性 CI runner 验收真实安装、TLS 与心跳。

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
node --test tests/rule_order.test.js tests/html_security.test.js tests/network_settings.test.js tests/template_session.test.js tests/agents.test.js tests/managed_nodes.test.js tests/subscription_export.test.js
ruff check --select E9,F63,F7,F82 .
python -m compileall -q main.py proxyforge agent scripts
python scripts/check_repository_privacy.py
```

CI 编译范围覆盖完整包；Mihomo 生成与 sing-box/systemd 工具同步使用新导入。保留测试目录和 fixture 相对路径，延续现有 unittest discovery 与 Node 测试入口。

## 9. 安全与隐私

分享链接解析和订阅生成不读取运行数据，不联网，不执行 shell。移动不降低验证门禁。构建仍使用 Docker 忽略规则排除私有数据、本地脚本和记忆；运维备份与隔离演练遵循[发布流程](RELEASE_ACCEPTANCE.md)。

## 10. 整理范围

本次不重写 UI、不引入前端构建链，不迁移运行数据。`main.py` 保留与管理提交和请求上下文相关的编排，机场运行状态集中在服务实例；后续若继续拆分路由，应显式注入存储依赖并覆盖事务/缓存行为，不能只为缩短文件而产生循环依赖。

## 11. 升级

升级完整 Controller checkout/镜像；不能只拷贝新的 `main.py` 而漏掉 `proxyforge/`。无需数据库 migration、凭据变更或 Agent 升级。先用生产冷备副本验收导入、订阅及管理接口，再切换服务。

## 12. 回滚

回退到整理前的完整 Controller 镜像/代码，schema 和数据格式兼容；不得混用新入口与旧根模块。数据恢复仅在确实发生数据问题时按发布流程进行，不因目录回退而覆盖用户的新配置。
