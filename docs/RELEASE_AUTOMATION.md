# 候选发布准备与正式发布

`scripts/prepare_release.py` 与手动触发的 `Prepare candidate release` 工作流负责固定提交的候选文件准备、隐私预检及重复校验。它们不创建 tag、不上传 GitHub Release、不改变 Latest、不推进安装 pin、不部署生产。首次正式 Controller 版本仍由所有者决定；工具示例不代表已存在的发布版本。

## 准备条件

先完成候选代码的审查合并与完整 CI，并核对实际 master 提交；PR 临时合并提交不能自动成为正式发布来源。根据[中文模板](RELEASE_NOTES_TEMPLATE.md)编写 `docs/releases/<版本>.md`，同代码一起提交并审查。标题版本必须与参数一致，八项中文说明不能留空或含“待填写”。当前所有者暂缓的独立网络、其他平台公网、裸机与 iOS Egern 验收须在限制中明确保留，不能改写成通过。

Controller SemVer、Agent 软件版本、schema 和能力协议各自独立，候选清单记录完整提交和兼容关系。版本不带 `v` 传给工具，预期 tag 为 `v<版本>`，准备工具还检查该 tag 能否被 Git 接受。旧包仍须使用与来源匹配的校验器，不能把新版本清单交给旧工具。

## 本地构建和自检

需要已审查 checkout、Git 和 Python 3.9+ 标准库，不需要 root 或第三方包。以下命令读取所有者已确定的版本；输出目录必须尚不存在。

```bash
set -euo pipefail
read -r -p '输入已确认的 Controller SemVer（不带 v）：' controller_version
commit=$(git rev-parse HEAD)
output=".local/release-candidate-$commit"
python3 -S scripts/prepare_release.py build --commit "$commit" \
  --version "$controller_version" --directory "$output"
metadata_sha256=$(python3 -S -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$output/release.json")
python3 -S scripts/prepare_release.py verify --commit "$commit" \
  --version "$controller_version" --directory "$output" --metadata-sha256 "$metadata_sha256"
```

这是本地自检。接收外部产物时，提交、版本和 `release.json` 的预期 SHA256 必须提前从可信发布记录固定，不能对下载清单自行算 hash 后称为来源认证。校验器也应来自可信版本。

工具只读取选定提交的 Git 对象，不读取工作树或暂存区的新改动、不执行所选提交的 Python。中文说明也来自同一提交；禁止用另一个未提交文件冒充配套说明。输出已存在则拒绝覆盖，构建失败可能留下本次不完整目录，保留排查并选择新目录。

## 五个候选文件

| 文件 | 含义 |
| --- | --- |
| `proxyforge-agent-<完整提交>.tar` | 既有 41 成员固定 Agent 包；不含 Controller 源码、运行数据或内核二进制 |
| `proxyforge-agent-<完整提交>.manifest.json` | 包与成员 hash、Controller 版本、独立 Agent/schema/能力兼容关系 |
| `RELEASE_NOTES.zh-CN.md` | 同提交的完整中文发布说明，保留原字节 |
| `release.json` | Controller 版本、预期 tag、完整提交、Agent/兼容关系、以上文件的名称/hash |
| `SHA256SUMS` | 其余四个文件按名称排序的 SHA256；自身不递归包含自己 |

`release.json` 的预期 hash 从可信工作流摘要或发布记录取得，再校验整套文件。清单、版本、提交、兼容信息、成员或校验和错配均拒绝；不接受额外文件、缺文件和符号链接，不解包、不安装、不执行内容。

准备前检查候选提交的全部跟踪路径，并对可用 UTF-8 解码的文件检查既有常见密钥/凭据 URL 模式；Git 对象必须为普通文件、单文件不超过 1 MiB。说明最多 128 KiB，release 元数据最多 64 KiB。此检查不是所有隐私的自动识别器，发布前仍须人工审查中文说明及所有待公开文件。

## 手动触发准备工作流

工作流只允许从 master 运行，完整提交必须属于该次 master 历史；输入通过环境变量传给校验器及加引号的命令，不作为 shell 程序插入。所有者确认版本并合并中文说明后，在 GitHub Actions 的 `Prepare candidate release` 页面输入这两个值，或在可信 checkout 执行：

```bash
set -euo pipefail
read -r -p '输入已确认的 Controller SemVer（不带 v）：' controller_version
commit=$(git rev-parse HEAD)
gh workflow run release-prepare.yml --ref master \
  -f source_commit="$commit" -f controller_version="$controller_version"
```

工作流先跑标准库产物专项，再准备并校验五个文件，只上传该输出目录；artifact 保留 14 天。它只有仓库内容读取权限，不能发布或部署。工作流自检不代替候选提交的完整 CI、审查或暂缓的外部验收。下载 artifact 后解压得到五个文件，再使用可信工作流摘要固定的 hash 运行上述 verify；Actions artifact 不是正式安装来源。

## 正式 tag 与 Release

先按[发布验收与恢复](RELEASE_ACCEPTANCE.md)核对门禁、备份及兼容边界。正式 tag/Release、Latest 与生产切换分别记录实际授权和结果；本工作流不会自动执行它们。所有者确认版本及具体候选后，维护者再创建不可混淆的完整提交 tag，核对远端 tag 指向与候选 `source_commit` 一致。

使用 [GitHub CLI 的 `--verify-tag`](https://cli.github.com/manual/gh_release_create) 创建草稿时，缺失远端 tag 应停止，不允许 CLI 自动创建 tag。只上传已校验的五个文件、使用同包中文 notes；不使用 `--clobber` 覆盖已发布资产。草稿应再次核对 tag、文件字节、版本/hash、中文说明和已测/未测范围后再发布；是否成为 Latest 单独决定。正式发布后的实际下载也要重新核对远端资产 hash。

本工具不提供升级现有 Agent 的自动覆盖路径。先升级 Controller，再按发布说明决定 Agent/helper 是否升级；完整备份、升级和回滚继续使用既有指南。版本标签、候选包和 CI 绿色都不证明已部署或公网验收完成。
