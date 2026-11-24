# ProxyForge

一体化节点控制面与多端订阅平台：集成 **五协议落地开荒与存量接管**、**`go-gost` 中转调度**、**多用户独立凭据与 `nftables` 内核态计费**、**多机场聚合清洗** 及 **五端订阅导出**，配套极简 Web 控制台与纯标准库 Linux Agent。

> 许可协议：[MIT](LICENSE)（第三方依赖及可选外部内核归属见 [许可证说明](docs/LICENSING.md)）。

## 核心能力

- **落地开荒与存量接管**：单机托管 **VLESS Reality**（本机 Caddy 回环“偷自己” / 外部目标）、**Hysteria2**（支持 `mport` 端口跳跃与 `salamander`）、**SS2022**、**AnyTLS** 与 **Trojan**（强制本机 Caddy Fallback）；支持同端口多节点 `auth_user` 分流、ACME（HTTP-01 / DNS-01）自动证书、三模 Caddy 伪装、多跳链式出站、元信息零停机热改，以及宿主机既有 `sing-box` / `xray` 扫描接管与一键归还。
- **中转调度与多用户配额**：Agent 托管 `go-gost` 实现 TCP/UDP 转发、多跳隧道与延迟优选，并可按转发规则自动重写订阅入口；为每个订阅用户确定性派生独立节点凭据，结合 `sing-box` `routing_mark` 与 `nftables` 内核态计数器统计真实上下行流量，支持每月自动重置、`Subscription-Userinfo` 头与超额自动断流。
- **多机场聚合与五端导出**：并发拉取上游机场并原子缓存（隔离环境代理、启用 DNS Pinning 与时间预算），与自建/托管/接管节点统一排序混排；原生导出 **Mihomo YAML**、**Sing-box JSON**、**Surge INI**、**Egern** 与 **标准 URI**，支持 `GEOSITE` / `GEOIP` / `DOMAIN-REGEX`、`,no-resolve` 及 DNS/TUN 防泄露预设。
- **零构建 Web 控制台与平滑运维**：浏览器可视化管理服务器、节点、中转、多用户订阅、代理组、路由规则与模板历史；内置 Komari 风格一键安装脚本与基于心跳校验的 Agent 静默平滑自升级。

## 快速部署（Docker Compose）

Controller 镜像基于 **Python 3.12 / Debian Bookworm**，默认以非 root 身份 **UID/GID `10001:10001`** 运行（详见 [容器权限说明](docs/CONTAINER_PERMISSIONS.md)）。

```bash
# 1. 获取代码并创建环境配置
git clone https://github.com/km-hl/ProxyForge.git
cd ProxyForge
cp .env.example .env

# 2. 初始化持久化数据目录（首次安装，尚无 ./data）
mkdir -m 0700 ./data
docker compose build --pull proxyforge
docker compose run --rm --no-deps --user 0:0 --entrypoint python \
  --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  proxyforge scripts/container_data.py --apply

# 3. 启动服务
docker compose up -d proxyforge
```

首次启动且未在 `.env` 中指定密钥时，系统会分别自动生成管理密钥与订阅密钥（两者严格隔离）：

```bash
# 查看首次生成的 Web 控制台管理密钥（登录后建议在控制台更换）
docker compose exec proxyforge cat /app/data/admin_token.txt

# 查看主订阅密钥
docker compose exec proxyforge python -c "import json; print(json.load(open('/app/data/config.json'))['subscription_token'])"
```

访问 `http://<服务器IP>:8000` 登录控制台（生产环境建议前置 HTTPS 反向代理，并在 `.env` 中配置 `PROXYFORGE_PUBLIC_URL="https://your-controller.example"`）。

## 接入 Agent 节点

支持 **Debian 12/13**、**Ubuntu 22.04/24.04**（`amd64` / `arm64`）、`systemd` 与系统 Python 3.9+（纯标准库，无第三方 Python 依赖）。

1. 在 `.env` 中配置 `PROXYFORGE_PUBLIC_URL` 后重启 Controller。
2. 在控制台 **「服务器与节点 → 添加服务器」** 中勾选所需组件（`--runtime`、`--with-gost`、`--adopt-scan`、`--gh-proxy` 等），复制一键命令到目标 VPS 执行。
3. 上线后的 Agent 会在心跳中比对包 SHA256 自动完成静默平滑升级；老版本 Agent 可在控制台使用 `--upgrade` 命令一次性引导升级。

详细参数、离线固定 Commit 校验安装及故障恢复见 [Agent 安装指南](docs/AGENT_INSTALL.md) 与 [Agent 运维说明](agent/README.zh-CN.md)。

## 订阅接口

| 入口 | 说明 |
| --- | --- |
| `GET /sub?token=<主订阅密钥>` | 主订阅，默认输出 Mihomo YAML；支持 `&format=singbox\|surge\|egern\|uri`、`&name=<名称>` 与 `&prefer_relay=1` |
| `GET /sub/{user_token}` | 多用户极简国内外分流订阅：按客户端 `User-Agent` 自动输出 Mihomo / Sing-box / Surge / Egern / URI（支持 `?target=` 覆盖），响应 `Subscription-Userinfo` |
| `GET /provider/{index}?token=<主订阅密钥>` | 上游机场独立 `proxy-provider` 代理出口（隐藏原始机场 URL） |

## 备份、升级与回滚

所有持久化状态均位于 `.env` 与 `data/`（含 `config.json`、`template.yaml`、`custom_nodes.yaml`、`airports.yaml`、模板历史、`proxyforge.db` 及加密密钥 `deployment.key`）。

1. **升级前冷备**：先执行 `docker compose stop proxyforge`，在目录外完整归档 `.env` 与 `data/`（**切勿在运行中仅拷贝 SQLite 主文件**）。
2. **拉取更新并启动**：`git pull` 后执行 `docker compose up -d --build proxyforge`；Controller 启动时自动在事务内完成数据库迁移（当前 `schema 8`）。
3. **回滚**：停止新容器，切回旧镜像/代码并恢复配套的整份 `data/` 冷备，切勿混用新旧版本的数据库与 `deployment.key`。

## 相关文档

- [Agent 安装指南](docs/AGENT_INSTALL.md) · [Agent 运维与恢复（中文）](agent/README.zh-CN.md) · [Agent README (EN)](agent/README.md)
- [非 root 容器权限与数据迁移](docs/CONTAINER_PERMISSIONS.md)
- [机场出站 HTTP、DNS Pinning 与私有 CA](docs/OUTBOUND_HTTP.md)
- [Egern 订阅导出契约](docs/EGERN_EXPORT.md)
- [项目目录结构与开发边界](docs/PROJECT_STRUCTURE.md)
- [依赖锁与构建输入](docs/DEPENDENCIES.md) · [Mihomo 兼容性测试](tests/mihomo/README.md) · [许可证说明](docs/LICENSING.md)
