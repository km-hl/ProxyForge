# ProxyForge 🛡️

ProxyForge 是一个专属的节点订阅聚合与配置下发中心。它可以作为你个人的后端服务，拉取购买的机场节点，无缝混入自建节点，并将它们与自定义的策略组和分流规则合并，最终通过 HTTP API 输出完整的 Clash/Mihomo YAML 配置文件。

## 核心特性
1. **伪装拉取**：请求头使用 `User-Agent: ClashForWindows/0.18.0` 以便机场直接返回 YAML 格式配置。
2. **代码与数据分离**：支持通过 `.env` 和外置的 `custom_nodes.yaml` 存储敏感数据，确保代码更新安全无冲突。
3. **模板注入**：基于预先配置的 `template.yaml`（包含策略组与规则），自动将合并后的所有节点和节点名称注入到对应的占位中。
4. **双重缓存与容错**：
   - **内存缓存**：内置 12 小时的内存级 TTL 缓存防机场封锁 IP。
   - **持久化备份**：拉取成功的配置会自动保存到本地磁盘（`data/airport_cache.yaml`）。当机场服务器宕机且缓存失效时，服务会自动回退到上一次成功的持久化备份，确保永不掉线。
5. **安全验证**：GET 接口受 URL Token 保护，防止配置被盗刷。

## 部署教程 (VPS 推荐)

> 推荐使用 Docker Compose 方式进行部署。在执行以下命令前，无需手动创建文件夹。

### 1. 克隆代码并进入目录
Git 会自动在当前目录下创建一个名为 `ProxyForge` 的文件夹。
```bash
git clone https://github.com/km-hl/ProxyForge.git
cd ProxyForge
```

### 2. 准备配置文件
复制提供的模板文件，这些带有您隐私数据的文件将被 `.gitignore` 自动忽略，绝不会被意外上传。
```bash
cp .env.example .env
cp custom_nodes.example.yaml custom_nodes.yaml
```

### 3. 编辑配置
使用 `nano` 或 `vim` 编辑这两个文件，填入您的真实信息：
- `.env`：填写您的机场订阅链接（`AIRPORT_SUB_URL`）和您的专属安全访问密钥（`SECRET_TOKEN`）。
- `custom_nodes.yaml`：填写您自己的私人节点（如果有的话）。

### 4. 启动服务 (Docker)
确保您的 VPS 安装了 Docker 和 Docker Compose，然后执行一键启动命令：
```bash
docker compose up -d
```
您的服务现在已经可以在后台安全运行了，并且会在 VPS 崩溃或重启时自动恢复！

---

## 客户端订阅

将以下链接添加到你的 Clash / Mihomo / Sing-box 等代理工具中进行订阅更新：
```text
http://<你的VPS公网IP或域名>:8000/sub?token=您的真实Token
```

## 日常更新指南

当您在本地电脑上修改了代码（例如更新了 `template.yaml` 里的策略组）并 Push 到 GitHub 后，在 VPS 上更新代码非常简单，且**绝对不会**覆盖或影响您的私有配置：

```bash
cd ProxyForge
# 1. 拉取最新代码
git pull
# 2. 重启 Docker 容器以应用更新
docker compose restart
```
