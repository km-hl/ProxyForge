# Agent 安装命令帮助（中文）

本页提供安装入口、参数和固定版本终端提示的中文对照。完整可复制的联网安装命令见[下载安装指南](AGENT_INSTALL.md)，恢复与卸载见[Agent 中文 README](../agent/README.zh-CN.md)。不必先取得源码目录才能首次安装。

已固定、已验证的 Agent 安装产物保留原英文终端输出，中文含义见下表；本文不改写固定产物或 SHA256。系统工具自身的错误还需结合具体退出状态处理。不要为翻译输出而修改校验值、关闭 TLS 或放宽 root 目录保护。

## 入口与参数

| 入口／参数 | 中文含义与限制 |
| --- | --- |
| 控制台“添加服务器” | 部署管理员设置 `PROXYFORGE_PUBLIC_URL` 后提供含可信 HTTPS 根地址的完整命令。先运行命令，终端提示隐藏输入时再生成一次性凭据 |
| bootstrap `install --server <HTTPS根地址>` | 首次安装普通 Agent；必须 root、受支持 Linux/systemd、Python 3.9+ 与控制终端；拒绝已有安装 |
| bootstrap `runtime` | 在同一固定来源的已安装 Agent 上，显式启用 root runtime helper；无需 `--server`，不接收注册凭据 |
| bootstrap `check` | 只下载、校验固定源码，不安装、不要求 root；不能视为已安装或已收到心跳 |
| bootstrap `--help` / `-h` | 显示三种动作及 `--server` 帮助；直接运行源码须使用 `python3 -I`，通常应使用完整已校验命令 |
| `sudo bash agent/install.sh <HTTPS根地址>` | 已有可信完整 checkout 时使用，只接受一个位置参数；交互隐藏读取 token，不接受 token 参数或单独下载的脚本 |
| `sudo bash agent/install-runtime.sh` | 已有可信匹配 checkout 和普通 Agent 时使用，不接受额外参数；创建 helper/units，尚不下载 sing-box |

两个 Bash 安装脚本不实现独立 `--help` 选项，参数数量错误时输出 Usage 并退出。首次安装、升级、恢复不是同一个动作：已有安装应使用[升级恢复流程](RELEASE_ACCEPTANCE.md)，不能通过删除凭据/实例 ID 强行让首次安装检查通过。

Controller 地址只接受 HTTPS 根地址，可带有效端口；不含用户名/密码、路径、query 或 fragment。域名使用 ASCII 完整域名或 punycode，IP 须满足公网地址检查。格式合法不等于 DNS、公网可达性或证书已经验收。

## 手动注册与运行参数

命令形式为 `python3 -m agent.main --config <配置路径> register|run`。全局 `--config` 位于子命令之前；生产手动恢复需以服务用户运行，完整示例见 [README](../agent/README.zh-CN.md)。

| 参数 | 所属命令 | 中文含义 |
| --- | --- | --- |
| `--config` | 全局 | 默认 `/etc/proxyforge-agent/config.json`；Unix 配置须 0600，目录私有。不要将内容粘贴到日志或工单 |
| `--server` | register，必需 | Controller 根地址，生产使用可信 HTTPS |
| `--token-stdin` | register，必需 | 从标准输入读取一次性凭据，不把 token 放入参数；注册只尝试一次 |
| `--ca-file` | register，可选 | 显式 CA 文件路径；服务用户必须可读，保留文件供后续运行验证 TLS |
| `--allow-insecure` | register，仅开发 | 允许本机开发 HTTP，**不能用于生产**；不表示 HTTPS 跳过证书校验 |
| `--once` | run，可选 | 发一次心跳并至多处理一个任务后退出；无此参数时循环运行 |
| `-h` / `--help` | 全局或子命令 | 查看原始参数名称；名称不翻译，含义按本表解释 |

凭据有效期 10 分钟，单次消费；注册响应丢失时先检查/移除孤儿记录，再签发新凭据恢复。已有完整凭据的配置拒绝重复注册。`run` 遇到凭据拒绝会退出 4，systemd 不自动重启该退出；恢复方法见 README。

## 安装器提示对照

| 原始提示（或固定开头） | 中文含义与处理 |
| --- | --- |
| `Usage: sudo bash agent/install.sh https://controller.example` | 需要 root 和一个 HTTPS 根地址参数；示例域名须替换为真实地址 |
| `Usage: sudo bash agent/install-runtime.sh` | helper 安装需要 root，不接受额外参数 |
| `Python3 and systemd required` | 缺少预期路径的 Python3 或 systemctl；先准备受支持主机 |
| `Python 3.9+ required` | 系统 Python 版本过低 |
| `Unsupported distribution or architecture` | 系统/架构不在允许矩阵；不要跳过检查 |
| `A root HTTPS controller URL is required` | 要求 HTTPS 根 URL；这里 root 指 URL 根路径，不是登录用户名 |
| `Existing Agent installation found` | 发现已有 Agent，未覆盖；按恢复/升级流程检查 |
| `Incomplete Agent distribution` | Agent 包缺失必要文件；重新核验完整来源，不执行残缺包 |
| `One-time registration token (hidden):` | 等待隐藏输入一次性注册凭据；粘贴后回车，不会回显 |
| `Inventory Agent installed. No sing-box deployment or firewall changes were made.` | 普通 Agent 已安装；未部署 sing-box 或改防火墙，仍须核对 Controller 心跳 |
| `Install Agent first` | 缺少普通 Agent 包或配置，先完成普通安装 |
| `Agent package must be root-owned and not group/world writable` | 安装包及父目录必须 root 所有且不允许其他用户写入；先调查目录来源/权限，不使用 777 |
| `Existing managed runtime path found; follow the upgrade/recovery guide` | 已有 runtime 路径，转到升级/恢复流程，不覆盖 |
| `Existing runtime unit found` | 已有同名 unit（含其他 systemd 搜索路径），先确认归属 |
| `Incomplete runtime distribution` | helper 包缺少必要模块、版本清单或 units |
| `Existing runtime account found; inspect it locally before provisioning` | 已有专用 runtime 账户，先在本地核对归属 |
| `Runtime helper enabled. Request the pinned installation from the Controller; no public listener is configured.` | helper 已启用，之后可从 Controller 请求固定版本安装；此时未配置公网监听 |
| `Bootstrap redirect rejected` | bootstrap 下载跳转被拒绝；核对官方固定 URL，不自动接受镜像 |
| `Bootstrap download failed` | bootstrap 下载失败；检查直连网络、可信 CA 和固定文件是否可用，不关闭 TLS 验证 |
| `Bootstrap SHA256 mismatch; nothing executed` | 下载内容或大小不符合预期，尚未执行；交由维护者核验固定版本，不现场重算 hash 替换预期值 |
| `Agent registered; credentials saved privately` | 注册成功且凭据已私密保存；接着检查服务与心跳 |
| `Agent operation failed. If enrollment was attempted...` | 注册或运行失败，输出有意不含秘密；如已尝试注册，先检查孤儿记录再用新凭据恢复 |
| `WARNING: insecure HTTP is for development only` | 当前使用显式开发 HTTP，不能用于生产 |
| `Agent credential revoked/rejected; synchronization stopped` | 凭据被撤销/拒绝，同步停止 |
| `Agent synchronization unavailable; retrying with backoff` | 暂时无法同步，按退避重试；检查服务和可信网络 |
| `Agent protocol incompatible; inventory only, update required` | 协议不兼容，仅清单模式；按 Controller 优先顺序升级配套组件 |

bootstrap 其余预检查/归档错误已经提供中文输出；更详细的失败后状态与恢复顺序见[安装故障表](AGENT_INSTALL.md)。不要把终端错误中没有 token 理解为可以分享配置文件。

## 维护者生成文档命令

在仓库根目录运行 `python -m scripts.agent_install_command --help` 可查看 CLI。`--bootstrap-commit` 必须为 40 位小写完整提交，`--bootstrap-sha256` 为随可信版本提供的 64 位小写摘要；`--action` 可选 install/runtime/check，默认 install；仅 install 使用 `--server`。

该工具只生成命令文本，不签发凭据或执行安装。新 pin 需先核验官方真实文件，再同步文档和控制台的共同实现及测试；不能使用 master/latest，也不能将下载后计算的摘要作为自证可信来源。
