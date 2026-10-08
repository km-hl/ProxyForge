# Egern 订阅导出

在控制台概览的“最终订阅配置”选择 **Egern**，复制链接导入 Egern 配置。最终预览使用所选格式，修改订阅名称或轮换订阅密钥后仍保留格式选择。原 Clash/Mihomo 链接和默认输出继续使用原格式。

API：`GET /sub?token=<订阅密钥>&format=egern&name=ProxyForge`。省略 `format` 或使用 `format=clash` 输出 Mihomo；未知格式返回 400，错误订阅凭据返回 401。管理凭据不进入链接。下载含节点秘密和规则集访问凭据，应私密保管。

## 转换范围

Egern 原生 YAML 使用 `proxies`、`policy_groups`、`rules`。转换基于当前订阅生成器的同一模板/节点快照，保留代理组顺序、默认首选、静态成员、机场来源、过滤条件与规则顺序，不修改保存的模板或节点。机场节点在输出时展开；名称保留旗帜及 provider 前缀，避免不同机场重名。

- 节点：Shadowsocks、Snell、Trojan、VMess、VLESS、Hysteria2、TUIC、AnyTLS、SOCKS5、HTTP、WireGuard 的可表达配置。
- VLESS/VMess：TCP、TLS/Reality、WS/WSS、TLS gRPC。Reality 公钥/short ID、Vision flow、SNI 和证书验证选择保留。VMess 使用 AEAD（alterId=0）。
- Shadowsocks 支持普通配置和 obfs HTTP/TLS；Trojan 支持普通 TLS 与 WebSocket；AnyTLS 显式保留证书验证，不采用 Egern 未配置时跳过验证的默认值。
- 代理组：select → select、url-test → auto_test、fallback → fallback、load-balance → load_balance；测速地址/间隔与容差保留，timeout 从毫秒换成秒。consistent-hashing/round-robin 映射为 hash/round_robin。
- 规则：域名、域名后缀/关键词/正则/通配、IP CIDR、国家 GEOIP、ASN、目的端口、NETWORK、AND/OR/NOT、MATCH。GEOSITE、非国家 GEOIP 及 RULE-SET 使用原生远端规则集，保持原规则位置和策略。`no-resolve` 继续生效。

不能表达的节点会被跳过，例如 XHTTP、SSR、VMess 旧认证、非 TLS gRPC、未支持的 SS plugin、WebSocket early data、多 peer WireGuard。被跳过的显式节点引用改为 REJECT；过滤或转换后空组使用 REJECT，防止原代理路径变为直连。全部节点都不兼容时返回 422。跳过数量写入 YAML 顶部注释和 `ProxyForge-Skipped-Nodes` 响应头。

uTLS client-fingerprint、Mihomo 专用复用/拥塞控制及部分性能参数不移植，Egern 使用自身实现。未支持的代理组、规则或负载策略返回明确 422，不能静默丢弃分流。REJECT-DROP 使用 Egern REJECT。Mihomo 的端口、DNS、TUN、Fake-IP、sniffer 与系统路由字段不直接复制；导出顶部和界面会提示在 Egern 中设置 DNS/TUN，不能据此宣称 DNS 防泄漏或真实客户端连接验收。

## 规则集服务

`GET /egern/ruleset/{kind}?token=<订阅密钥>&value=<类别或规则集名>`，kind 为 geosite、geoip 或 provider。该接口沿用独立订阅鉴权，不接受调用者提供下载 URL。

GEOSITE/非国家 GEOIP 从 [MetaCubeX 官方规则数据](https://github.com/MetaCubeX/meta-rules-dat) 的 meta 分支读取对应 YAML，转换为 Egern 域名/IP 集合；管理员自定义 Mihomo geodata 数据库未转换。自定义数据库与该来源不同的场景应改用显式 RULE-SET，以免假定两份类别内容完全一致。类别拒绝路径穿越和 URL。

旧 `GEOIP,lan` 使用 private 地址集合，国家代码规范为大写。provider 使用保存的 `rule-providers` 定义，URL 中携带定义 SHA256 revision；定义变化时拒绝旧链接并要求更新配置。支持 HTTP 来源的 YAML/text、domain/ipcidr/classical 条件，不支持 MRS、本地文件或未支持条件。规则集内容失败不会以空集返回成功。

新下载复用现有安全出站：每跳 DNS 校验并固定连接 IP、系统 CA、忽略环境代理、总预算 30 秒、最大 8 MiB。规则资源最多 4 个同时下载，成功结果在进程内缓存 4 小时，总缓存上限 32 MiB；失败不缓存。展开额外 proxy-provider 时也使用安全出站与 60 秒共享预算。正常 YAML 响应使用 no-store，错误只返回位置/固定说明，不回显 URL 或规则/节点秘密。

## 验证、部署与恢复

```bash
python -m unittest discover -s tests -p test_egern_export.py -v
node --test tests/subscription_export.test.js
```

测试使用公开样本，验证真实 /sub 默认与 Egern 响应、鉴权、Reality/WS/gRPC 映射、机场命名、过滤/空组、规则顺序/no-resolve、逻辑条件、资源边界和 revision 失效。继续运行完整 Python/Node、Mihomo、容器与 Agent CI。Egern 没有在本仓库可用的官方 CLI parser；结构/接口验证不等于已在 iOS Egern 中完成导入或节点握手。

不新增依赖、数据库 schema、Agent 协议或持久化业务格式。部署前按[发布验收](RELEASE_ACCEPTANCE.md)制作完整冷备并验证副本，旧 root 数据按[权限迁移](CONTAINER_PERMISSIONS.md)准备；恢复原镜像、Compose 与对应数据挂载即可回退。只更新 Controller，无需升级 Agent。

格式依据核对于 2026-10-08：[代理](https://egernapp.com/docs/configuration/proxies/)、[策略组及订阅格式](https://egernapp.com/docs/configuration/policy_groups/)、[规则及规则集](https://egernapp.com/docs/configuration/rules/)。后续 Egern 格式变更需同时更新转换器、测试和本页。
