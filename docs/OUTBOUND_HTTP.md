# 机场 HTTP 请求：独立 Session 与显式信任

本文实现[开发计划](NEXT_STEPS.md)第 5 项的第一阶段：关闭机场请求对进程环境代理、默认凭据和 CA 路径的隐式继承。适用于节点拉取、机场信息及使用相同拉取逻辑的后台刷新；不改变 Agent 网络行为。

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

Docker Compose 的现有 `./data:/app/data` 挂载下，先将经过核验的 PEM CA 文件保存为宿主的 `./data/airport-ca.pem`，再配置上述容器内路径。原生部署应填写该进程可读的绝对路径。这里需要的是可信 CA 公共证书，不要放入服务器私钥。

修改后重启 Controller；使用 Compose 时通过 `docker compose up -d --build --force-recreate proxyforge` 使更新后的 `.env` 生效。该命令会重建服务，执行前遵循项目的发布验收流程。

留空采用 Requests 默认 CA。自定义文件替换默认 bundle，而非自动附加；如果还要访问公共 CA 签发的机场，提供同时包含所需公共根证书与私有根证书的受控 bundle。不存在、不可读、损坏的文件或主机名不符会导致请求失败，不会降级到 `verify=False`。该选项只由部署环境提供，Web API 和订阅参数不能指定 CA 文件或关闭验证。

内部接口新增关键字参数 `safe_get(..., ca_bundle: Optional[str] = None)`。`None` 保持验证开启；非空字符串作为显式 CA 路径；布尔值和空路径拒绝。`main.py` 启动读取专用环境选项，将其同时传给节点与信息拉取入口。显式 CA 的行为参见 [Requests TLS 验证说明](https://requests.readthedocs.io/en/stable/user/advanced/#ssl-cert-verification)。

## 跳转、响应与关闭

继续只接受 HTTP/HTTPS，校验字面地址和每跳全部解析结果；私有、保留地址或公网/私网混合结果拒绝。最多跟随 3 次跳转，每次发送前重新校验目的地。

Requests 在 `allow_redirects=False` 时仍可能为 `Response.next` 预读跳转响应体。私有 `_OutboundSession` 禁用这条隐式准备路径，由 `safe_get` 独占跳转处理：取得 Location 后关闭跳转响应，不读取其正文，再校验下一跳。正常正文仍按 64 KiB 流读取，对声明长度及实际解码字节检查 10 MiB 上限。超限、流中断、缺失 Location、跳转超限和验证失败都释放已取得的响应及 Session。

最终响应在关闭连接前已缓存正文；调用方仍能使用 `text`、`content`、`headers`、`status_code` 和 `raise_for_status()`。HTTP 错误码继续交给调用方判断。路径、响应对象的主要语义和现有缓存格式保持兼容；不承诺保留 Requests 自动生成的 `Response.next`。

## 尚未解决的边界

本阶段没有固定连接 IP。DNS 校验与实际连接之间仍可能发生解析变化，因此不能把 `trust_env=False` 当作 DNS rebinding 已修复；DNS pinning、Host/SNI/证书匹配与连接池策略属于下一阶段。

30 秒连接/读取等待、响应大小和跳转次数也不是整个请求或刷新批次的总期限。DNS 等待和持续缓慢响应仍需后续总预算设计；本阶段保持[后台关闭文档](AIRPORT_BACKGROUND.md)中的限制。

## 验证、升级与回滚

`tests/test_outbound_session.py` 使用真实 Requests 请求准备和环境合并，在适配器发送边界拦截外网访问，验证代理/CA/NETRC 隔离、逐跳校验、响应限制与关闭、Cookie 隔离、并发 Session 独立、显式 CA 和两个机场调用方。前三项回归在旧实现复现失败。

`tests/test_outbound_tls.py` 动态生成临时测试 CA/服务器证书，在本机回环 HTTPS 服务验证显式 CA 成功、环境 CA 不被继承、主机名错误及缺失 CA 失败。仅此隔离测试绕过公网 URL 校验，以访问测试监听器；它不证明生产 DNS pinning 或公网连通性。证书和私钥随临时目录清理，不提交测试私钥。

升级前核对是否依赖环境代理、NETRC 或环境 CA；前两项不再受支持，需要 Controller 能直接连接机场并使用明确的订阅身份。需要私有 CA 时按专用配置迁移。节点已有缓存仍可按原逻辑回退；机场信息的错误结果仍缓存 24 小时，纠正配置并重启后可在控制台强制刷新。

无需数据库或 Agent 升级。本项回滚使用先前完整 Controller 镜像/代码，保留运行配置及缓存；旧版不识别新 CA 选项，并恢复对原环境代理/凭据/CA 的继承，回滚时须核对这些部署设置。发布操作仍遵循[发布验收流程](RELEASE_ACCEPTANCE.md)，本 PR 不包含部署。
