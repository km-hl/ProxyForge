# Agent 固定安装产物

本工具完成开发计划第 14 项的安装产物准备：从完整 Git 提交生成最小代码包、中文操作说明与 SHA256 清单。它不创建正式版本、上传 Release、安装服务或生成注册 token。第 16 项第一阶段现已提供[官方固定源码 bootstrap 与完整命令](AGENT_INSTALL.md)，包含安全解包及 root 目录检查；控制台入口已随 #41 合并，Ubuntu 24.04 amd64 安装/HTTPS 心跳已验证，CI 本次扩为 Ubuntu 四组合，结果按对应提交核对；Debian 与公网矩阵仍待完成，当前不要把 CI 包当作已发布的安装版本。

## 构建与校验命令

在已审查的 ProxyForge checkout 根目录运行以下 Bash 命令。需要 Git 和 Python 3.9+ 标准库，无第三方依赖、网络下载或 root 权限。`git rev-parse HEAD` 将当前已审查提交解析为完整 40 位 ID；构建器只接受完整小写 ID，不接受 `master`、`latest`、tag 或短 ID。

```bash
set -euo pipefail
commit=$(git rev-parse HEAD)
output=".local/agent-artifacts/$commit"
python3 scripts/agent_artifacts.py build --commit "$commit" --output-dir "$output"
manifest="$output/proxyforge-agent-$commit.manifest.json"
archive="$output/proxyforge-agent-$commit.tar"
manifest_sha256=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$manifest")
python3 scripts/agent_artifacts.py verify --commit "$commit" \
  --manifest-sha256 "$manifest_sha256" --manifest "$manifest" --archive "$archive"
```

这是维护者**本地构建自检**命令。输出目录必须尚不存在；再次构建时选择新目录。构建读取 Git blob，不读取工作树的改动，不执行选定提交的 Python 代码；修改后必须先提交才能打包。构建工具自身也必须来自已审查的可信 checkout。

接收别人提供的包时，使用同一个 `verify` 命令，但 `--commit` 与 `--manifest-sha256` 必须由可信发布记录提前固定，**不能自行对刚下载的清单算 hash 再当作可信输入**。命令要求调用者显式传入这两个值；校验器也必须通过可信渠道取得并固定版本。SHA256 用于检测与可信预期的偏差，不等于代码签名或来源认证。

当前没有本功能的正式 Release 下载地址、签名或自动更新源。正式分发前需确认项目许可证、版本号，审查并发布完整提交与 manifest 的 SHA256；不能从任意镜像同时获取包和 hash 后宣称已认证来源。首次安装、恢复、升级与卸载见 [Agent 中文说明](../agent/README.zh-CN.md)；已有安装仍拒绝覆盖。

## 产物契约（format 1）

| 字段/文件 | 含义 |
| --- | --- |
| `proxyforge-agent-<完整提交>.tar` | 无压缩 USTAR；仅固定清单中的 Agent 文件与配套说明，没有 Controller、Git 数据、运行凭据或 sing-box 二进制 |
| `proxyforge-agent-<完整提交>.manifest.json` | 固定格式 UTF-8 JSON；自身 SHA256 由构建命令输出，需在可信发布记录保存 |
| `format` | 安装清单格式，当前为 1；与 Agent 协议版本无关 |
| `source_commit` | Agent 来源的完整提交 |
| `agent_version` | 从该提交 `agent/__init__.py` 的字面值读取；当前 0.6.0 |
| `controller_release_version` | 当前为 `null`，尚未指定正式 Controller release tag |
| `controller_source_commit` | 配套 Controller 来源提交，与 Agent 同提交；不是允许任意旧 Controller 的兼容承诺 |
| `compatibility` | Python 3.9+、systemd、OS/架构允许列表、Controller schema 基线 5，以及清单/任务/runtime/部署/落地/链路各自协议版本 1 |
| `archive` | 规范文件名、字节数、完整 tar 的 SHA256 |
| `files` | 每个成员的路径、字节数、SHA256 和规范模式 `0644` |

`agent/install-compatibility.json` 是受审查的安装兼容契约；变更平台、协议或 schema 基线时需同步构建校验器及测试。helper 默认关闭，包内包含其代码不代表安装、启动或宣告能力。先升级 Controller，再逐台升级 Agent/helper；数据库 schema 不是 Agent 软件版本。

所有成员按路径排序，时间戳为 0，uid/gid 为 0，用户名/组名为空。使用不压缩 tar 避免 gzip 时间戳和压缩库差异，同一提交的包与清单可重复比较；这不代表 Controller 容器镜像逐字节可复现。归档元数据中的 uid 0 **不证明磁盘文件实际由 root 控制**。

## 校验与安全边界

校验顺序为：manifest 大小与预期 SHA256 → 提交匹配 → tar 大小与 SHA256 → 每个成员 → 规范归档与完整清单逐字节比对。拒绝缺文件、多文件、重复文件、绝对/穿越路径、符号/硬链接、设备、目录、PAX 扩展、尾随数据、非规范权限/所有者、成员 hash 或兼容信息不一致。清单最多 64 KiB，包最多 8 MiB，单文件最多 1 MiB。

`verify` **只读并验证，不解包、不执行安装脚本**。验证成功也不允许随后将普通用户可替换的包/目录直接作为 root 代码执行；消费此最小包的 bootstrap 必须在 root 控制的目录中对同一份内容完成校验、有限解包及所有权检查后才运行脚本。当前完整安装命令使用另行固定的官方源码归档，见[安装指南](AGENT_INSTALL.md)。不要以 `tar -xf ... && sudo bash ...` 拼成未经审查的一键安装。

失败返回非零，不开始注册；构建过程中 I/O 失败可能留下不完整的新输出目录，保留检查并换新目录重建。不会覆盖旧目录，也不会自行删除文件。

## 自动化验证与尚未验证的范围

```bash
python3 -S -m unittest discover -s tests -p test_agent_artifacts.py -v
```

测试覆盖重复构建、工作树污染隔离、Git 链接/缺失文件拒绝、manifest 固定、篡改及恶意归档；从包中还原的临时副本执行 `python -S -m agent.main --help`，检查模块齐全。CI 在 Python 3.9–3.13 执行这些测试，并从本次 CI 的完整提交实际构建、自检；PR 的临时合并提交只用于验证，不自动成为发布版本。

这些证据不代替 Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64 的空白主机特权安装矩阵、实际公网 HTTPS 注册与心跳、helper 安装或生产升级。每项实际验证状态应随正式发布记录维护，参见 [发布验收与恢复](RELEASE_ACCEPTANCE.md)。

中文文档补齐后，最小包新增 `docs/AGENT_INSTALL_HELP.md`，共 24 个 Agent 文件、13 份配套说明。构建和校验必须使用与目标提交匹配的工具清单；旧提交缺少新增文档时，新工具会拒绝构建，旧包仍用原提交的工具验证。固定 bootstrap 的源码提交及 hash 未因此改变。最小包不包含整个仓库：开发计划/完整文档索引请在官方仓库对应提交中阅读。
