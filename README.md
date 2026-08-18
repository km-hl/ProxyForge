# ProxyForge 🛡️

ProxyForge 是一个**全可视化**的专属节点订阅聚合与配置下发中心。它可以作为你个人的后端服务，拉取购买的多个机场节点，无缝混入自建节点，并将它们与自定义的策略组和分流规则智能合并，最终通过 HTTP API 输出完整的 Clash/Mihomo YAML 配置文件。

## ✨ 核心亮点

1. **🎨 全可视化 Web 仪表盘 (Web UI)**
   - 抛弃繁琐的 YAML 文本编辑。只需在浏览器中打开 Web UI，即可通过现代化的界面管理一切。
   - 所有接口与界面均受您的专属 `Token` 保护。

2. **✈️ 多机场聚合与自建节点融合**
   - 支持添加任意数量的机场订阅。
   - 每个机场会作为独立的 Mihomo `proxy-provider` 下发，代理组通过 `use` 引用；原始机场订阅地址由 ProxyForge 代理，不会暴露在最终配置里。
   - 可视化添加并管理您的自建节点，支持直接粘贴 `vmess://`、`vless://`、`trojan://`、`hysteria2://`、`hy2://`、`ss://` 分享链接自动转换为 Mihomo YAML 节点。
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

6. **🔒 极致安全的持久化备份**
   - 所有的配置更改均会实时持久化到本地。当机场服务器宕机时，服务会自动回退到最新的持久化备份，确保**永不掉线**。

---

## 🚀 部署教程 (VPS 推荐)

> 推荐使用 Docker Compose 方式进行部署。一键拉起，简单无忧。

### 1. 克隆代码并进入目录
```bash
git clone https://github.com/km-hl/ProxyForge.git
cd ProxyForge
```

### 2. 启动服务 (Docker)
确保您的 VPS 安装了 Docker 和 Docker Compose，然后执行一键启动命令：
```bash
docker compose up -d
```
您的服务现在已经可以在后台安全运行了，并且会在 VPS 崩溃或重启时自动恢复！

---

## 🎮 如何使用 Web 控制台

1. 浏览器访问：`http://<您的VPS公网IP>:8000` (首次访问会自动提示设置您的安全密钥 `Token`，可以在`.env`文件中自定义端口号)。
2. 登录后，您可以在界面上：
   - 在 **概览设置** 生成您的专属客户端订阅链接。
   - 在 **机场订阅** 中批量添加您购买的机场链接。
   - 在 **自建节点** 中直接添加 YAML 节点，或粘贴分享链接自动解析。
   - 在 **代理组** 中设计您的多层级分流逻辑，使用**智能筛选**一键匹配节点。
   - 在 **路由规则** 中拖拽排布分流优先级。

将生成的订阅链接添加到您的 Clash Verge / Mihomo / Sing-box 即可享受私人定制的科学上网体验！

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

- `.env` (您的安全验证密钥)
- `data/` 文件夹（包含 `template.yaml`、`custom_nodes.yaml`、`airports.yaml` 和节点缓存）

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
