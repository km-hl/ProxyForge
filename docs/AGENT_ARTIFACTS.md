# Agent 固定安装产物

本工具完成开发计划第 14 项的安装产物准备：从完整 Git 提交生成最小代码包、中文操作说明与 SHA256 清单。它不创建正式版本、上传 Release、安装服务或生成注册 token。第 16 项第一阶段现已提供[官方固定源码 bootstrap 与完整命令](AGENT_INSTALL.md)，包含安全解包及 root 目录检查；控制台入口已随 #41 合并，Ubuntu 24.04 amd64 安装/HTTPS 心跳已验证，CI 本次扩为 Ubuntu 四组合，结果按对应提交核对；Debian 同架构 systemd 容器 CI 见[验收边界](AGENT_INSTALL_DEBIAN_CI.md)，完整 Debian VM 四组合已随 #48 实测，Debian 12 amd64 公网注册/心跳/队列/helper 已验收，独立网络、其他平台公网与裸机仍待，当前不要把 CI 包当作已发布的安装版本。

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

当前没有本功能的正式 Release 下载地址、签名或自动更新源。MIT 已由所有者选择，项目及第三方条款见[许可说明](LICENSING.md)；首个 Controller 正式版本号已确定为 v0.7.0；正式分发仍须审查并发布完整提交与 manifest 的 SHA256；不能从任意镜像同时获取包和 hash 后宣称已认证来源。首次安装、恢复、升级与卸载见 [Agent 中文说明](../agent/README.zh-CN.md)；已有安装仍拒绝覆盖。

## 产物契约（format 1）

| 字段/文件 | 含义 |
| --- | --- |
| `proxyforge-agent-<完整提交>.tar` | 无压缩 USTAR；仅固定清单中的 Agent 文件与配套说明，没有 Controller、Git 数据、运行凭据或 sing-box 二进制 |
| `proxyforge-agent-<完整提交>.manifest.json` | 固定格式 UTF-8 JSON；自身 SHA256 由构建命令输出，需在可信发布记录保存 |
| `format` | 安装清单格式，当前为 1；与 Agent 协议版本无关 |
| `source_commit` | Agent 来源的完整提交 |
| `agent_version` | 从该提交 `agent/__init__.py` 的字面值读取；当前 0.6.0 |
| `controller_release_version` | 默认 `null`；构建时可显式指定独立的 Controller SemVer，校验时须独立提供同一预期值；不表示已创建 tag/Release |
| `controller_source_commit` | 配套 Controller 来源提交，与 Agent 同提交；不是允许任意旧 Controller 的兼容承诺 |
| `compatibility` | Python 3.9+、systemd、OS/架构允许列表、Controller schema 基线 5，以及清单/任务/runtime/部署/落地/链路各自协议版本 1 |
| `archive` | 规范文件名、字节数、完整 tar 的 SHA256 |
| `files` | 每个成员的路径、字节数、SHA256 和规范模式 `0644` |

`agent/install-compatibility.json` 是受审查的安装兼容契约；变更平台、协议或 schema 基线时需同步构建校验器及测试。helper 默认关闭，包内包含其代码不代表安装、启动或宣告能力。先升级 Controller，再逐台升级 Agent/helper；数据库 schema 不是 Agent 软件版本。

### 为候选发布固定 Controller 版本

所有者确定版本后，构建和校验均可传入 `--controller-release-version`。采用 [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html)，值为不带 `v` 的版本号；支持预发布标识和构建元信息，最长 128 个 ASCII 字符。主/次/补丁号以及纯数字预发布标识不得有前导零；构建元信息允许前导零。未来 tag 可使用 `v` 前缀，但传给工具的值不含它。

以下 Bash 命令会交互读取所有者已决定的版本，不预设首个版本。它只创建本地候选包和清单，不创建 tag、不上传 Release，也不推进安装来源。

```bash
set -euo pipefail
read -r -p '输入已确认的 Controller SemVer（不带 v）：' controller_version
commit=$(git rev-parse HEAD)
output=$(python3 -c 'import tempfile; print(tempfile.mkdtemp(prefix="proxyforge-release-"))')/artifacts
python3 scripts/agent_artifacts.py build --commit "$commit" --output-dir "$output" \
  --controller-release-version "$controller_version"
manifest="$output/proxyforge-agent-$commit.manifest.json"
archive="$output/proxyforge-agent-$commit.tar"
manifest_sha256=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$manifest")
python3 scripts/agent_artifacts.py verify --commit "$commit" \
  --controller-release-version "$controller_version" \
  --manifest-sha256 "$manifest_sha256" --manifest "$manifest" --archive "$archive"
```

这仍是本地自检；接收外部产物时，完整提交、manifest SHA256 和 Controller 版本均须来自可信发布记录，不能从下载的清单自动读取版本后传回校验器。遗漏、不同版本或显式版本与 `null` 互换均拒绝，即使调用方重新计算了清单 hash，也不能跳过元数据一致性检查。

同一源码的 Agent tar 不因 Controller 版本标签而变化，manifest 的版本字段及 SHA256 会变化；同一提交与同一版本可重复构建。Agent 软件版本仍从 Agent 源码读取，schema/能力协议仍按原兼容契约校验。旧的无版本命令、format 1 及 `null` 清单行为保持；带版本的新清单须使用本功能版本的校验器，旧工具会拒绝它。接受一个候选版本标签不证明对应 tag 存在、CI 通过、正式发布或已部署，这些门禁仍见[发布验收](RELEASE_ACCEPTANCE.md)。

所有成员按路径排序，时间戳为 0，uid/gid 为 0，用户名/组名为空。使用不压缩 tar 避免 gzip 时间戳和压缩库差异，同一提交的包与清单可重复比较；这不代表 Controller 容器镜像逐字节可复现。归档元数据中的 uid 0 **不证明磁盘文件实际由 root 控制**。

## 校验与安全边界

校验顺序为：manifest 大小与预期 SHA256 → 提交匹配 → tar 大小与 SHA256 → 每个成员 → 规范归档与完整清单逐字节比对。拒绝缺文件、多文件、重复文件、绝对/穿越路径、符号/硬链接、设备、目录、PAX 扩展、尾随数据、非规范权限/所有者、成员 hash 或兼容信息不一致。清单最多 64 KiB，包最多 8 MiB，单文件最多 1 MiB。

`verify` **只读并验证，不解包、不执行安装脚本**。验证成功也不允许随后将普通用户可替换的包/目录直接作为 root 代码执行；消费此最小包的 bootstrap 必须在 root 控制的目录中对同一份内容完成校验、有限解包及所有权检查后才运行脚本。当前完整安装命令使用另行固定的官方源码归档，见[安装指南](AGENT_INSTALL.md)。不要以 `tar -xf ... && sudo bash ...` 拼成未经审查的一键安装。

失败返回非零，不开始注册；构建过程中 I/O 失败可能留下不完整的新输出目录，保留检查并换新目录重建。不会覆盖旧目录，也不会自行删除文件。

## 自动化验证与尚未验证的范围

```bash
python3 -S -m unittest discover -s tests -p test_agent_artifacts.py -v
python3 -S -m unittest discover -s tests -p test_controller_release_metadata.py -v
```

测试覆盖重复构建、工作树污染隔离、Git 链接/缺失文件拒绝、manifest 固定、篡改及恶意归档；从包中还原的临时副本执行 `python -S -m agent.main --help`，检查模块齐全。CI 在 Python 3.9–3.13 执行这些测试，并从本次 CI 的完整提交实际构建、自检；PR 的临时合并提交只用于验证，不自动成为发布版本。

这些证据不代替 Debian 12/13、Ubuntu 22.04/24.04 × amd64/arm64 的空白主机特权安装矩阵、实际公网 HTTPS 注册与心跳、helper 安装或生产升级。每项实际验证状态应随正式发布记录维护，参见 [发布验收与恢复](RELEASE_ACCEPTANCE.md)。

中文文档补齐后，最小包包含 `docs/AGENT_INSTALL_HELP.md`，本次另加入 `docs/AGENT_INSTALL_DEBIAN_CI.md` 避免安装指南链接缺失，此前共 24 个 Agent 文件、14 份配套说明。本批再加入根 LICENSE、agent/LICENSE 与 docs/LICENSING.md；现为 25 个 Agent 文件、15 份配套说明及 1 个根许可，共 41 成员。源码安装的 Agent 与 helper 同样携带许可副本。构建和校验必须使用与目标提交匹配的工具清单；旧提交缺少新增文档时，新工具会拒绝构建，旧包仍用原提交的工具验证。加入中文说明本身不推动固定安装锚点；后续 helper unit 的降权修复已更新固定源码、bootstrap 提交及 SHA256，当前值以[完整安装命令](AGENT_INSTALL.md)为准。最小包不包含整个仓库：开发计划/完整文档索引请在官方仓库对应提交中阅读。
