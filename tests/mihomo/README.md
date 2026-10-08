# Mihomo 解析兼容性测试

运行时静态校验器与真实解析样例共同以 **v1.19.31** 为基线。Python 测试读取同一 manifest，检查静态接受条件及配置不被修改。有意保留的差异必须声明 `static_valid` 和 `static_difference` 原因，例如为未来 TUN stack 保留配置并警告。CI 还用 `generation/` 中公开样本调用真实 `build_subscription_config()`，把输出 YAML 交给同一二进制。32 个手工样例与生成样例分别报告。

## 固定版本

`release.json` 是版本、Linux amd64 compatible 资产与压缩包 SHA256 的共同来源。摘要来自[官方资产页](https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.31)。下载器只使用 `MetaCubeX/mihomo` GitHub Releases，HTTP/校验失败即停止，先验证归档再提取可执行文件。不将二进制加入生产 Docker 镜像或请求处理路径。

## 本地运行（Linux amd64）

在仓库根目录运行。下载器/解析器仅用 Python 3.9+ 标准库；调用真实应用生成配置则按当前 Controller 矩阵使用 Python 3.12/3.13 和锁定依赖，建议在独立虚拟环境执行：

```bash
python3 scripts/download_mihomo.py --output .local/mihomo/v1.19.31/mihomo
.local/mihomo/v1.19.31/mihomo -v
.local/mihomo/v1.19.31/mihomo -h
python3 scripts/check_mihomo.py --binary .local/mihomo/v1.19.31/mihomo
python3 -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements.txt
python3 scripts/generate_ci_config.py --output test-results/mihomo/generated-subscription.yaml
python3 scripts/check_mihomo.py --binary .local/mihomo/v1.19.31/mihomo \
  --generated-config test-results/mihomo/generated-subscription.yaml
```

复现 CI 的网络隔离需要 Linux `unshare`、`ip` 及创建网络命名空间的权限（通常用 sudo）：

```bash
sudo unshare --net -- bash -euc '
  ip link set lo up
  "$1" scripts/generate_ci_config.py --output test-results/mihomo/generated-subscription.yaml
  exec "$1" scripts/check_mihomo.py --binary "$2" --log-dir test-results/mihomo \
    --generated-config test-results/mihomo/generated-subscription.yaml
' _ "$(command -v python3)" "$PWD/.local/mihomo/v1.19.31/mihomo"
```

命名空间仅开启回环接口（含 IPv6），不需要代理服务、机场、订阅凭据、下载规则集或 geodata。DNS 使用文档示例 IP，fallback 显式关闭 GeoIP 过滤。普通本地运行不强制断外网，上述 CI 命令才提供该隔离。

运行器执行 `mihomo -t -d <独立空临时目录> -f <样例绝对路径>`。CLI/test 模式依据固定版本 [main.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/main.go)。每例独立目录和进程，并移除环境配置覆盖。设置上游 [config/utils.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/utils.go) 中的 `SKIP_SYSTEM_IPV6_CHECK=true`，让无全局 IPv6 的 CI 主机也检查 IPv6 地址池解析；样例顶层 `ipv6: false` 仍会禁用该池。

每次调用默认超时 30 秒，超时算失败。日志及 `results.json` 写入 Git 忽略的 `test-results/mihomo/`；解析预期失败时 CI 仍上传日志。

## 真实生成订阅

`scripts/generate_ci_config.py` 在临时工作目录导入真正的 `main.py`，禁用 dotenv 自动发现，为临时运行存储提供公开测试凭据；不提取 AST 副本或 mock builder。成功/失败后恢复临时目录、环境、导入路径和模块注册。应用诊断输出到 stderr，stdout（或 `--output`）只含 UTF-8 YAML。不需要生产文件或 Docker 改动。

输入模板覆盖 `_custom_nodes_` 展开、默认节点顺序、旗帜装饰、规则目标重写，以及 DNS/TUN 和内联 rule provider。自建节点是 127.0.0.1:1080 上的虚构 SOCKS5 端点，不要求真实服务或机场。生成器的两处静态校验都执行，之后序列化并交给真实 parser。单元测试观察真实函数，验证调用、无关 DNS/TUN 值保留，并与调用者 `.env`、环境 token 和运行数据隔离。

`--generated-config` 可重复指定。缺失/空文件在启动 Mihomo 前失败，否则内核可能在缺失路径创建默认配置。CI 产物包含生成文件、逐例日志和 `results.json`；生成和解析样本时禁用外网。

## 覆盖与维护

`cases.json` 对每个 YAML 样例恰好列一次。正例必须退出 0 且出现成功标记；负例必须退出 1、出现失败标记及指定诊断。崩溃或无关错误不能视为满足负例。

- 正例：最小默认值、Fake-IP/零 TTL、标量或列表 DNS 策略、内联规则 provider 引用、代理 DNS 策略、基本/严格 TUN、IPv6/cache/fallback 高级 DNS、null 块及标量。
- 负例：启用 DNS 时 nameserver 为空/null、DNS 字段类型错误、缺失 proxy DNS 策略依赖、IPv4 地址池族错误、两个地址池都为空、缺失 rule-provider 引用。
- 扩展基线：仅 IPv6 地址池、IPv6 族/前缀错误、IPv4/IPv6 容量不足、顶层禁用 IPv6、数值/null 边界、normal DNS 模式、Mips stack、TUN 字段类型及 proxy policy provider 行为。

解析成功不证明连通性、路由安装、DNS 防泄漏、缓存行为或其他系统/版本兼容。CI 只绕过主机 IPv6 可用性检测，不绕过配置顶层 IPv6 开关，也不建立真实 IPv6 连通。`-t` 不执行平台相关的 TUN 行为。

## 静态校验边界

`proxyforge/config/mihomo_compat.py` 记录选定原始默认值、类型及固定源码依据。已有 UI 默认值保留，新增投影包括 use-hosts/use-system-hosts=true、IPv6 timeout=100、fake-IP TTL=1 及 TUN IPv6 地址。缓存原始默认仍为空算法字符串和大小 0；运行时 resolver 回退 LRU/4096，不反写 YAML。

TTL/cache 的硬限制仅为整数表示范围，基线允许零和有符号负数；负数及 float→int 转换会警告。未知 cache 字符串提示 LRU 回退。空策略列表/字符串警告，null 策略值则拒绝，因为基线 ToStringSlice 对 null 会 panic。接受 normal DNS 模式及 Mips/大小写不敏感 stack 名。这些修正基于源码/parser，不能沿用旧假设。

未来字段保留并给 info；未来 stack/filter 模式和复杂 matcher 语义仍只做部分检查，因此静态通过不保证任意用户配置都被固定内核接受。TUN 检查类型、数值位宽和地址语法，不强加服务器平台限制。

升级时核对固定源码和 Release 摘要，以证据更新预期，并跑正负例；不能把解析错误改为无条件成功，或删除失败样例让 CI 变绿。

## 尚存边界与技术债

- 生成场景不穷尽用户 YAML、机场 provider、协议组合或所有客户端 Mihomo 版本。
- 复杂 matcher/geodata、平台特性仍为部分静态检查，未完全复现内核 YAML 类型转换。
- `main.py` 导入仍初始化存储；开发工具将其隔离，应用工厂或纯 builder 提取仍待后续实现。
- 当前应用依赖已按[依赖锁说明](../../docs/DEPENDENCIES.md)固定版本和哈希，Mihomo 的 tag/架构/资产/摘要也固定；这仍不保证 runner 工具链完全固定或整个构建逐字节一致。
- 高级字段 UI、二进制缓存和首次支持版本追踪是否继续扩展，由后续任务决定，不是本 parser 测试的验收要求。
