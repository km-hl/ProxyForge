# 机场 HTTP 请求：独立 Session、DNS pinning 与显式信任

本文说明[开发计划](NEXT_STEPS.md)第 5 项已实现的 Session 隔离与 DNS pinning：关闭环境代理、默认凭据和 CA 路径的隐式继承，并将每跳实际 TCP 连接固定到该跳已验证的 IP。单次请求和批次网络预算见[出站时间预算](OUTBOUND_BUDGETS.md)。适用于节点拉取、机场信息及使用相同拉取逻辑的后台刷新；不改变 Agent 网络行为。

## 请求边界

`proxyforge/security/network_security.py:safe_get` 每次调用创建独立的 Requests Session，设置 `trust_env=False`，所有成功与异常退出路径均关闭 Session。Session 不跨调用或线程共享。

- `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及其小写形式不再决定机场请求的代理；`NO_PROXY` 也不再参与选路。
- `.netrc`、`_netrc` 和 `NETRC` 指定文件中的默认身份不再自动加入请求。显式订阅 URL 中的身份信息仍保持既有行为，不能把它写入日志。
- `REQUESTS_CA_BUNDLE`、`CURL_CA_BUNDLE` 不再覆盖机场请求的证书信任。默认使用当前 Requests 安装所提供的 CA，始终保留证书链及主机名校验。
- 每一跳开始前清空 Session 的 CookieJar，保持此前逐次 `requests.get` 不重放服务端 Cookie 的行为。

以上改变只约束应用使用的 Requests 配置，不代表能绕过系统路由、透明代理或宿主网络设置。环境选项行为依据 [Requests 的 trust_env 与验证设置](https://requests.readthedocs.io/en/stable/api/)及[官方 Session 实现](https://requests.readthedocs.io/en/latest/_modules/requests/sessions/)。

## 显式自定义 CA

部署管理员可以在 `.env` 中设置专用选项：

```dotenv
PROXYFORGE_AIRPORT_CA_BUNDLE="/app/data/airport-ca.pem"
```

Docker Compose 的现有 `./data:/app/data` 挂载下，先将经过核验的 PEM CA 文件保存为宿主的 `./data/airport-ca.pem`，再配置上述容器内路径。非 root 容器要求文件属于 `10001:10001` 且权限为 `0600`，目录准备和迁移见[容器权限说明](CONTAINER_PERMISSIONS.md)。原生部署应填写该进程可读的绝对路径。这里需要的是可信 CA 公共证书，不要放入服务器私钥。

修改后重启 Controller；使用 Compose 时通过 `docker compose up -d --build --force-recreate proxyforge` 使更新后的 `.env` 生效。该命令会重建服务，执行前遵循项目的发布验收流程。

留空采用 Requests 默认 CA。自定义文件替换默认 bundle，而非自动附加；如果还要访问公共 CA 签发的机场，提供同时包含所需公共根证书与私有根证书的受控 bundle。不存在、不可读、损坏的文件或主机名不符会导致请求失败，不会降级到 `verify=False`。该选项只由部署环境提供，Web API 和订阅参数不能指定 CA 文件或关闭验证。

内部接口新增关键字参数 `safe_get(..., ca_bundle: Optional[str] = None)`。`None` 保持验证开启；非空字符串作为显式 CA 路径；布尔值和空路径拒绝。`main.py` 启动读取专用环境选项，将其同时传给节点与信息拉取入口。显式 CA 的行为参见 [Requests TLS 验证说明](https://requests.readthedocs.io/en/stable/user/advanced/#ssl-cert-verification)。

## DNS pinning 与 TLS 身份

每一跳先用 Requests 准备规范化 URL（包括 IDNA 域名、转义和端口），再校验实际发送的 URL。系统解析器只调用一次；取得全部结果后，拒绝空结果、私有/保留/组播地址、带作用域的 IPv6，以及公网与这些地址混合的结果。全部通过后才允许建立连接，保留解析器返回顺序并去重。

每跳私有 `_PinnedAdapter` 使用 Requests 的连接池配置和 TLS 验证路径，只在该池实例上替换连接构造器。`_PinnedConnectionMixin._new_conn` 使用数字 IPv4/IPv6 地址直接 `socket.connect`，不调用 urllib3 默认的二次域名解析。TCP 连接失败可以依次尝试**本次已验证集合**中的下一地址；HTTP 自动重试关闭，失败后不刷新 DNS。IPv6 使用无作用域的四元组地址。

URL 和连接对象的主机名始终保留原域名；Host 从规范化 URL 的 authority 生成（包含显式端口、排除用户身份），覆盖调用者传入的 Host。HTTPS 继续由 urllib3 使用原域名发送 SNI、验证证书链和主机名。证书仅匹配连接 IP、但不匹配 URL 域名时仍拒绝。参考 [Requests 适配器实现](https://requests.readthedocs.io/en/latest/_modules/requests/adapters/)和 [urllib3 的 SNI/主机名说明](https://urllib3.readthedocs.io/en/stable/advanced-usage.html#custom-sni-hostname)。

响应退出时关闭该跳连接池；相同域名的重定向也必须重新解析、验证和连接，不共享上一跳或另一调用的 TCP 连接。适配器拒绝 URL 被改写或启用代理。没有全局 DNS/连接池 monkeypatch，也没有关闭证书验证的路径。直接依赖约束写入 `requirements.in`，精确版本和哈希仍由[依赖锁](DEPENDENCIES.md)管理；Requests/urllib3 升级必须通过真实 TCP/TLS 回归。

## 跳转、响应与关闭

继续只接受 HTTP/HTTPS，校验字面地址和每跳全部解析结果；私有、保留地址或公网/私网混合结果拒绝。最多跟随 3 次跳转，每次发送前重新校验目的地。

Requests 在 `allow_redirects=False` 时仍可能为 `Response.next` 预读跳转响应体。私有 `_OutboundSession` 禁用这条隐式准备路径，由 `safe_get` 独占跳转处理：取得 Location 后关闭跳转响应，不读取其正文，再校验下一跳。正常正文仍按 64 KiB 流读取，对声明长度及实际解码字节检查 10 MiB 上限。超限、流中断、缺失 Location、跳转超限和验证失败都释放已取得的响应及 Session。

最终响应在关闭连接前已缓存正文；调用方仍能使用 `text`、`content`、`headers`、`status_code` 和 `raise_for_status()`。HTTP 错误码继续交给调用方判断。路径、响应对象的主要语义和现有缓存格式保持兼容；不承诺保留 Requests 自动生成的 `Response.next`。

## 尚未解决的边界

DNS pinning 关闭了应用校验后由连接层再次解析到其他 IP 的窗口；它不替代宿主防火墙、路由和出口控制，也不保证公网服务本身可信。操作系统解析器和网络配置仍属于部署的信任边界。

默认保留 30 秒连接/读取等待，并增加 60 秒单次网络总预算、每跳最多 10 秒 DNS 等待、每批 180 秒网络预算和最多 8 个系统解析槽位。截止时间覆盖地址切换、TLS、跳转及持续滴流；停止标志传入活动请求，迟到 DNS 结果不能连接。

这些预算不能强杀 CPU 解析、配置锁或磁盘操作，也不是进程退出的硬上限。内部接口、容量耗尽、过期队列/缓存行为及升级影响见[出站时间预算](OUTBOUND_BUDGETS.md)，后台额外等待仍遵循[生命周期说明](AIRPORT_BACKGROUND.md)。

## 验证、升级与回滚

`tests/test_outbound_session.py` 使用真实 Requests 请求准备和环境合并，在适配器发送边界拦截外网访问，验证代理/CA/NETRC 隔离、逐跳校验、响应限制与关闭、Cookie 隔离、并发 Session 独立、显式 CA 和两个机场调用方。前三项回归在旧实现复现失败。

`tests/test_outbound_pinning.py` 在受控回环 HTTP 服务记录真实 `socket.connect` 目标；模拟 DNS 第一次返回允许的测试地址、第二次返回另一私有地址，断言只解析一次并连到第一地址。覆盖 IPv4/IPv6、每跳和每次调用的新连接、同源跳转 DNS 变为内网时拒绝、IDNA/Host、地址切换、失败关闭、连接池释放，以及私有/保留/组播/作用域/混合结果拒绝。旧实现会在二次 DNS 解析处使 rebinding 回归失败。

`tests/test_outbound_tls.py` 动态生成临时 CA、域名和 IP 服务器证书，在真实回环 HTTPS 上记录 TCP 目的地、Host 和 SNI，验证域名证书、自定义 CA、环境 CA 隔离及缺失 CA；特别验证“证书匹配固定 IP、却不匹配原域名”必须失败。测试仅局部允许监听器的回环地址，生产地址分类另有拒绝测试；没有模拟 TCP/TLS 成功，也不声称验证了真实公网机场。证书和私钥随临时目录清理，不提交测试私钥。

升级前核对是否依赖环境代理、NETRC 或环境 CA；前两项不再受支持，需要 Controller 能直接连接机场并使用明确的订阅身份。需要私有 CA 时按专用配置迁移。节点已有缓存仍可按原逻辑回退；机场信息的错误结果仍缓存 24 小时，纠正配置并重启后可在控制台强制刷新。

无需数据库或 Agent 升级。本项回滚使用先前完整 Controller 镜像/代码及其匹配依赖锁，保留运行配置及缓存。退回仅有 Session 隔离的版本会重新开放 DNS 校验到连接的窗口；若再退回 Session 隔离之前，旧版还不识别专用 CA 选项，并恢复对环境代理/凭据/CA 的继承，须核对部署设置。发布操作仍遵循[发布验收流程](RELEASE_ACCEPTANCE.md)，本 PR 不包含部署。
