# ProxyForge 🛡️

ProxyForge 是一个专属的节点订阅聚合与配置下发中心。它可以作为你个人的后端服务，拉取购买的机场节点，混入自建节点，并将它们与自定义的策略组和分流规则合并，最终通过 HTTP API 输出完整的 Clash/Mihomo YAML 配置文件。

## 核心功能
1. **伪装拉取**：请求头使用 `User-Agent: ClashForWindows/0.18.0` 以便机场直接返回 YAML 格式配置。
2. **数据合并**：提取机场节点并无缝混入本地定义的自建节点。
3. **模板注入**：基于预先配置的 `template.yaml`（包含策略组与规则），自动将合并后的所有节点和节点名称注入到对应的占位中。
4. **缓存与容错**：内置 12 小时的内存级 TTL 缓存防机场封锁 IP。如果在缓存失效时拉取失败，会自动回退（Fallback）到最后一次成功的缓存数据，或仅返回自建节点。
5. **安全验证**：GET 接口受 URL Token 保护，防止配置被盗刷。

## 运行环境
- Python 3.8+

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 项目配置
- **配置机场链接与密钥**：编辑 `main.py`，配置以下变量（或通过环境变量传入）：
  - `AIRPORT_SUB_URL` = `"https://你的机场订阅链接"`
  - `SECRET_TOKEN` = `"你的专属安全Token"`
  - `MY_CUSTOM_PROXIES` = 你的自建节点列表配置。
- **自定义模板**：编辑 `template.yaml`，按自己的偏好定制端口、模式、`proxy-groups` 策略组以及 `rules` 分流规则。

### 3. 启动服务
在本地或 VPS 上运行：
```bash
python main.py
```
或者使用 `uvicorn` 直接启动：
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. 客户端订阅
将以下链接添加到你的 Clash / Mihomo / Sing-box / 代理工具中进行订阅更新：
```text
http://<你的IP或域名>:8000/sub?token=my_secret_token
```

## 注意事项
- 由于使用了内存缓存 (`TTLCache`)，每次重启服务端，缓存会被重置。
- 如果你的策略组有特殊的排除逻辑，可以在 `main.py` 中的 `template_config["proxy-groups"]` 遍历逻辑中添加过滤条件。
