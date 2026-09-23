# ProxyForge 🛡️

ProxyForge 是一个**全可视化**的专属节点订阅聚合与配置下发中心。它可以作为你个人的后端服务，拉取购买的多个机场节点，无缝混入自建节点，并将它们与自定义的策略组和分流规则智能合并，最终通过 HTTP API 输出完整的 Clash/Mihomo YAML 配置文件。

## ✨ 核心亮点

1. **🎨 全可视化 Web 仪表盘 (Web UI)**
   - 抛弃繁琐的 YAML 文本编辑。只需在浏览器中打开 Web UI，即可通过现代化的界面管理一切。
   - Web 控制台使用独立管理密钥和 HttpOnly 会话 Cookie；客户端订阅密钥只允许访问 `/sub` 与 `/provider`，不能调用管理 API。

2. **✈️ 多机场聚合与自建节点融合**
   - 支持添加任意数量的机场订阅。
   - 每个机场会作为独立的 Mihomo `proxy-provider` 下发，代理组通过 `use` 引用；原始机场订阅地址由 ProxyForge 代理，不会暴露在最终配置里。
   - 可视化添加并管理您的自建节点，支持直接粘贴 `vmess://`、`vless://`、`trojan://`、`hysteria2://`、`hy2://`、`ss://`、`tuic://`、`anytls://`、`wireguard://` 分享链接自动转换为 Mihomo YAML 节点。
   - TUIC 支持 v4 `token` 与 v5 `uuid + password`；AnyTLS 按 Mihomo 原生字段输出，不会把不受支持的 AnyTLS+Reality 静默降级。AnyTLS 节点需要客户端使用支持该协议的较新 Mihomo 内核。
   - WireGuard 支持私钥、公钥、双栈客户端地址、Allowed IPs、预共享密钥、Reserved、MTU、DNS 和 Persistent Keepalive；链接中的 CIDR 地址会转换为 Mihomo 的独立 `ip` / `ipv6` 字段。
   - 节点名称会根据地区关键词自动显示国旗，并在下发 YAML 时同步加到节点名与代理组引用中；已有国旗的节点不会重复添加。

3. **📁 智能代理组 (Proxy Groups) 引擎**
   - **智能筛选 (Smart Include)**：告别手动挑选节点！只需勾选地区（如香港、日本）和来源（如某机场、自建节点），ProxyForge 会在后台自动完成交集过滤。
   - 支持拖拽嵌套、批量操作节点与组。

4. **📏 分流规则 (Rules) 完全可视化**
   - 支持直观地添加、编辑 `rules` 和 `rule-providers`。
   - **丝滑拖拽排序**：鼠标按住即可拖拽调整路由规则的优先级，操作即存即用。
   - 保存模板和生成最终订阅前会执行静态可用性检查，包括节点必填字段、代理组/provider 引用、规则目标、`RULE-SET` 引用和代理组循环，并在错误时返回具体位置。
   - 删除或重命名自建节点、机场时，会自动清理代理组中对应的 `proxies` / `use` 悬空引用；旧配置在启动时也会自动迁移清理。

5. **⚡ 零延迟热更新与后台守护 (Daemon)**
   - **全自动缓存刷新**：内置后台守护协程，每 4 小时静默拉取并更新所有机场数据。
   - **0 延迟体验**：当您的代理客户端发起拉取请求时，服务器会直接下发热腾腾的缓存数据，不再有转圈等待。

6. **🔒 持久化备份与故障回退**
   - 所有配置更改都会持久化到 `data/`。机场服务器暂时不可用时，服务会按机场回退到最近一次成功缓存；如果该机场从未成功缓存，则明确返回错误而不是下发空配置。

---

## 🚀 部署教程 (VPS 推荐)

> 推荐使用 Docker Compose 方式进行部署。一键拉起，简单无忧。

### 1. 克隆代码并进入目录
```bash
git clone https://github.com/km-hl/ProxyForge.git
cd ProxyForge
```

### 2. 创建环境配置
```bash
cp .env.example .env
```

您可以编辑 `.env` 修改监听端口。`SECRET_TOKEN` 是客户端订阅密钥；`ADMIN_TOKEN` 是 Web 控制台管理密钥，两者必须分开。留空时系统会分别自动生成：订阅密钥持久化到 `data/config.json`，首次管理密钥写入权限为 `0600` 的 `data/admin_token.txt`。

### 3. 启动服务 (Docker)
确保您的 VPS 安装了 Docker 和 Docker Compose，然后执行：
```bash
docker compose up -d --build
```

首次启动或从旧版本升级后，可使用下面的命令读取管理密钥：

```bash
docker compose exec proxyforge cat /app/data/admin_token.txt
```

登录后请在 WebUI 中更换管理密钥；更换后 `admin_token.txt` 会自动删除。需要查看客户端订阅密钥时使用：

```bash
docker compose exec proxyforge python -c "import json; print(json.load(open('/app/data/config.json'))['subscription_token'])"
```
您的服务现在已经可以在后台安全运行了，并且会在 VPS 崩溃或重启时自动恢复！

---

## 🎮 如何使用 Web 控制台

1. 浏览器访问：`http://<您的VPS公网IP>:8000`，输入上一步获得的管理密钥。生产环境建议使用带 HTTPS 的反向代理。
2. 登录后，您可以在界面上：
   - 在 **概览设置** 生成您的专属客户端订阅链接。
   - 在 **机场订阅** 中批量添加您购买的机场链接。
   - 在 **自建节点** 中直接添加 YAML 节点，或粘贴分享链接自动解析。
   - 在 **代理组** 中设计您的多层级分流逻辑，使用**智能筛选**一键匹配节点。
   - 在 **路由规则** 中拖拽排布分流优先级。

将生成的订阅链接添加到 Mihomo / Clash.Meta 兼容客户端（例如 Clash Verge Rev）即可使用。当前 `/sub` 输出为 Mihomo YAML，不是原生 Sing-box JSON。

## 🛡️ DNS 与网络

在侧边栏的 **DNS 与网络** 页面可配置 Mihomo DNS、Fake-IP / Redir-Host、IPv6 DNS、DoH / DoT / UDP / TCP 地址、Bootstrap 和代理节点域名 DNS、Direct Nameserver、DNS 分流策略、Fake-IP Filter，以及 TUN、DNS Hijack 和 Strict Route。

- **兼容模式**仅关闭订阅内 TUN，保留原有 DNS；**防 DNS 泄露**提供 DNS/TUN 起始配置；**严格防泄露**额外启用 Strict Route。预设先展示实际字段变更，确认后写入草稿，点击“保存网络设置”才持久化。原有自定义字段保留，普通预设不会关闭已有 Strict Route。
- DNS 服务商快捷选择提供常用地址，用户可以继续修改；国内/国外推荐策略只新增缺失项，不覆盖同名策略。原有 `nameserver-policy` 字符串值和列表值均可读取。
- 网络页面、底层 YAML 和最终订阅共用 `data/template.yaml`，没有独立 DNS 配置文件。页面切换不会写入默认值。保存成功后刷新相关界面；失败保留草稿，存在另一页未保存草稿时会阻止覆盖。
- 未知 Mihomo 字段按值保留，包括 `dns` / `tun` 内高级字段。可视化保存会重新序列化 YAML，不保证保留注释、引号、锚点写法或排版。高级 YAML 预览只读，完整编辑仍在“底层配置兜底”。
- 配置检查区分 **错误**、**建议**和**未验证**：错误阻止保存和最终订阅生成；建议允许保存。新增 `/api/template/validate` 只校验、不写文件、不访问 DNS 服务；使用既有管理鉴权。原有模板 API 请求及成功响应保持不变。

静态默认值与必填条件以 [Mihomo v1.19.31 配置源码](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go) 为基线，版本、默认值及字段定义集中在 `mihomo_compat.py`。字段缺失与显式空列表不同，例如缺少 `nameserver` 时内核可采用默认值，但启用 DNS 后显式 `nameserver: []` 会被拒绝；`respect-rules: true` 或非空 `proxy-server-nameserver-policy` 都要求非空的 `proxy-server-nameserver`。

高级 DNS 字段（IPv6 Fake-IP 地址池、TTL、IPv6 超时、缓存与策略 DNS）和 TUN 路由、接口、UID 等字段支持 Raw YAML 保留及基础校验，不要求通过普通 UI 编辑。原有默认值未改写进模板；`fake-ip-ttl` 默认 1、`ipv6-timeout` 默认 100，缓存原始零值与运行时 LRU/4096 回退分开处理。Fake-IP 允许在客户端 IPv6 条件满足时仅使用 IPv6 地址池，两个池不能同时禁用。平台行为、复杂 matcher 和 geodata 仍有未验证范围。

更新版本的协议栈或高级 Filter 模式会保留并标注兼容性范围；本服务无法获知每个客户端的内核版本，也不替代 Mihomo 完整配置解析。默认/空值语义参照固定版本源码与 YAML 解码规则，尚不等价于逐版本二进制验收。

开发 CI 另设 Mihomo 兼容性任务：下载固定的官方 **v1.19.31 Linux amd64** 二进制并校验 SHA256，在隔离外网的环境中对配置正反例执行真实 `-t` 解析测试。Python 测试使用同一组 fixtures 验证静态结论，并记录为了保留未来字段而允许的差异。目前尚未将实际订阅生成结果接入真实内核测试。运行方式与覆盖边界见 [Mihomo 测试说明](tests/mihomo/README.md)。解析通过不代表所有用户配置、客户端平台或实际网络行为均已验证。

这些配置用于降低 DNS 泄露风险，实际结果仍受操作系统、浏览器、客户端覆盖配置及网络环境影响。预设 Bootstrap 包含明文 DNS；配置 DoH 不等于所有查询均加密或经代理。关闭 IPv6 DNS 不等于关闭系统 IPv6。Strict Route 依赖 auto-route，可能影响部分应用；服务器不会修改客户端的路由、防火墙或 TUN 权限。

概览显示的是已保存模板的静态配置状态，最终订阅预览仍来自真实 `/sub` 输出。此功能不进行真实 DNS 泄露检测。多浏览器同时修改模板尚无版本冲突保护，全局导入仍可能部分成功。

## 🔄 日常更新代码指南

当有新功能推送到 GitHub 后，在 VPS 上更新代码非常简单，且**绝对不会**覆盖或影响您的私有配置：

```bash
set -e
cd ProxyForge
git pull --ff-only
docker compose up -d --build
```

`template.example.yaml` 只是仓库默认模板。Web UI 修改的真实配置保存在
`data/template.yaml`，因此日常 `git pull` 不会再与用户配置冲突。

升级到凭据分离版本时，原有 `secret_token` 会原样迁移为客户端订阅密钥，因此现有客户端链接不会变化。系统会另行生成管理密钥，其 PBKDF2 哈希保存在 `data/config.json`，首次明文写入 `data/admin_token.txt`；请用部署章节中的命令读取并登录，然后在 WebUI 中更换。公开示例订阅密钥 `my_secret_token` 仍会自动轮换。

更新完成后，请在 Clash Verge / Mihomo 中重新更新 ProxyForge 订阅，并刷新一次“代理集合”。机场节点由独立的 `proxy-provider` 二次加载，仅更新主订阅但保留旧 provider 缓存时，客户端可能暂时仍显示旧状态。

### 机场 `proxy-provider` 的工作方式

ProxyForge 不会把所有机场节点平铺到顶层 `proxies`。每个机场会生成一个独立 provider，代理组通过 `use` 引用：

```yaml
proxy-providers:
  LiangXin:
    type: http
    url: https://proxyforge.example/provider/0?token=YOUR_TOKEN
    path: ./proxy_providers/proxyforge_1.yaml

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    use:
      - LiangXin
      - PeiQian
      - Mitce
      - SakuraCat
```

客户端访问 `/provider/{index}` 时，ProxyForge 会拉取对应机场并返回标准 Mihomo provider 文档：

```yaml
proxies:
  - name: Example Node
    type: vless
    # ...
```

原始机场订阅 URL 不会出现在最终配置中。需要注意：HTTP provider 响应顶层必须是 `proxies`；`payload` 仅用于 `type: inline`，不能作为 HTTP provider 文件的顶层键。

### 机场组显示 `COMPATIBLE` 且没有节点

这通常表示代理组还在，但 Clash/Mihomo 没有成功下载或解析 provider，并不代表机场已被删除。请按顺序检查：

1. 确认服务器已拉取最新代码并重新构建容器。
2. 在客户端更新主订阅，再到“代理集合”中强制刷新各机场 provider；必要时重启 Mihomo 内核。
3. 在服务器或可信终端测试 provider 接口（请勿泄露真实 Token）：

   ```bash
   curl -fsS "https://<ProxyForge域名>/provider/0?token=<TOKEN>" | head
   ```

   正常响应第一行应为 `proxies:`。
4. 检查最终订阅中 `proxy-providers.*.url` 是否是客户端能访问的公网 HTTPS 地址。若使用 Nginx、Caddy 或 Cloudflare 反向代理，请确保正确传递 Host 和原始协议。
5. 查看服务日志：

   ```bash
   docker compose logs --tail=200 proxyforge
   ```

常见状态码：

- `401`：provider URL 中的 Token 不正确。
- `404`：机场索引不存在，通常需要重新更新主订阅。
- `422`：机场节点字段未通过 Mihomo 静态校验。
- `502`：机场当前拉取失败，并且没有该机场的可用缓存。

### 从旧版 `template.yaml` 一次性升级

旧版服务器首次升级到新存储结构时，需要先保留根目录中的运行配置：

```bash
set -e
cd /root/ProxyForge
cp template.yaml /root/ProxyForge-template.backup.yaml
git restore template.yaml
git pull --ff-only
mkdir -p data
cp /root/ProxyForge-template.backup.yaml data/template.yaml
if [ -f custom_nodes.yaml ]; then cp custom_nodes.yaml data/custom_nodes.yaml; fi
docker compose up -d --build
```

确认 Web UI 中的代理组和规则正常后，可以删除仓库外的备份文件。此后使用上面的日常更新命令即可。

---

## 📦 数据迁移指南 (如何无损迁移到新 VPS)

ProxyForge 的所有核心数据和配置均以纯文本文件的形式持久化保存在当前目录下。如果您更换了 VPS 或需要备份，只需带走以下几个核心文件即可完美还原：

- `.env`（监听端口和首次迁移参数）
- `data/` 文件夹（包含 `config.json`、`template.yaml`、`custom_nodes.yaml`、`airports.yaml` 和节点缓存；若尚未在 WebUI 更换首次管理密钥，还包括 `admin_token.txt`）

**迁移步骤：**
1. 在新 VPS 上克隆项目并进入目录：
   ```bash
   git clone https://github.com/km-hl/ProxyForge.git
   cd ProxyForge
   ```
2. 将旧 VPS 上 ProxyForge 目录下的 `.env` 以及整个 `data` 文件夹复制到新服务器。旧版备份中的根目录 `template.yaml` 和 `custom_nodes.yaml` 请分别复制为 `data/template.yaml` 和 `data/custom_nodes.yaml`。
3. 在新 VPS 上启动容器：
   ```bash
   docker compose up -d
   ```
   大功告成！您之前所有的节点、配置、筛选规则都会瞬间满血复活，并且客户端的订阅链接完全不需要改变（只需把域名解析或 IP 换成新的即可）。
