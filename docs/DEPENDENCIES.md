# 依赖锁与构建输入

Controller 的直接依赖在 `requirements.in` 人工维护，`requirements.txt` 是包含全部传递依赖、精确版本和 SHA256 的生成文件。开发依赖受同一生产锁约束。正常安装只读取锁文件，不重新选择最新依赖。

## 文件与支持范围

| 输入 → 锁文件 | 用途 |
| --- | --- |
| `requirements.in` → `requirements.txt` | Controller 生产依赖；Docker、Mihomo 生成与 sing-box/systemd 验收共用 |
| `requirements-dev.in` → `requirements-dev.txt` | 完整生产依赖加测试与 Ruff；通过 `-c requirements.txt` 保持生产版本 |
| `requirements-legacy.in` → `requirements-legacy.txt` | 仅供 Python 3.9 冷恢复对照镜像，不用于生产或 Agent |
| `requirements-lock.in` → `requirements-lock.txt` | 固定生成器 uv 0.11.19 及其分发包哈希，只装在维护工具环境 |

统一锁采用 uv 的 universal 解析，保留 Python/平台条件标记及分发包哈希；生产/开发解析下限为 3.12，旧版对照为 3.9。解析可表达其他环境并不意味着支持所有环境：Controller 实测矩阵为 **CPython 3.12/3.13、Linux amd64 和 Windows amd64** 的锁安装，完整应用 CI 仍以 Linux 为准。实际容器为 Linux amd64；arm64 容器与 macOS/PyPy 尚未验收。Agent 继续只依赖系统 Python 标准库，不使用以上锁。

基础镜像固定为 `python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3`。digest 是官方多架构索引，目标平台选择其固定子镜像。恢复脚本中的旧版 `3.9.25-slim-bookworm` 也固定 digest，使用独立旧版依赖锁。

首次生产锁沿用 PR #34 真实镜像验收中的版本。Python、Debian 或依赖有安全更新时，应修改输入/镜像引用、重新生成并经 PR 验证；锁定不是永久停止更新。

## 安装

Linux 源码部署示例（先进入仓库）：

```bash
python3.12 -m venv .local/runtime
.local/runtime/bin/python -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements.txt
.local/runtime/bin/python -m pip check
```

开发环境使用独立 venv，将最后的输入改为 `requirements-dev.txt`。Windows 使用 `py -3.13 -m venv .local/runtime` 创建环境，Python 路径改为 `.local/runtime/Scripts/python.exe`。不要在包含无关包的旧环境中声称安装结果可复现；切换服务前仍需按[运行时升级说明](PYTHON_RUNTIME.md)备份和验收。

Docker 与 CI 同样启用 `--require-hashes --only-binary=:all:`：缺失哈希、内容不符或没有目标平台 wheel 时失败，不临时回退源码构建，也不临时移除哈希限制。首次构建和安装需要联网；索引可用性不由锁文件保证。

## 重新生成

使用单独工具环境，避免将 uv 加入生产环境：

```bash
python3.12 -m venv .local/lock-tools
.local/lock-tools/bin/python -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements-lock.txt
python3.12 scripts/lock_dependencies.py --uv .local/lock-tools/bin/uv
```

Windows 对应命令：

```powershell
py -3.13 -m venv .local/lock-tools
.local/lock-tools/Scripts/python.exe -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements-lock.txt
py -3.13 scripts/lock_dependencies.py --uv .local/lock-tools/Scripts/uv.exe
```

脚本核对 uv 精确版本，按生产→开发→旧版→工具顺序生成四份锁，清除 `UV_*` / `PIP_*` 环境覆盖并禁用 uv 配置文件，固定使用官方 PyPI。普通运行尽量保留既有锁定版本；主动升级可加 `--upgrade`，然后审查全部版本、哈希和条件标记的变化。不要手工编辑生成的 `.txt`。

更新 uv 本身时，同步修改 `requirements-lock.in` 和脚本版本常量；先用当前已校验的生成器为新 uv 生成工具锁，再创建新工具环境，使用新版本重新生成全部文件并检查差异。工具锁和基础镜像 digest 的修改也必须进入 PR。

## 验证与回滚

```bash
python scripts/check_dependency_locks.py
python scripts/check_controller_image.py docker
```

第一条使用当前 3.12/3.13 解释器创建两套临时环境，在每套环境安装生产锁、记录版本，再安装开发锁。每次安装后执行 `pip check`，检查开发锁未改变生产版本，两套环境版本集合一致；比较排除解释器自带的 pip/setuptools。随后实际下载一个篡改哈希的依赖，必须因哈希不匹配失败。临时环境自动清理，不修改当前环境。

CI 在 Linux/Windows × 3.12/3.13 执行上述安装验收；Linux 3.12 还用固定工具重生成全部锁并要求 Git 无差异。完整 Python/Node、真实 Mihomo、sing-box/systemd 及带锁的镜像冷恢复也必须通过。第二条需要 Docker，使用合成数据独立卷，边界见[运行时说明](PYTHON_RUNTIME.md)。

同一提交、同一目标平台可重复得到相同的应用依赖版本与允许的包内容；这**不等于整个镜像逐字节可复现**。安装时间戳、构建工具/宿主环境等仍可影响镜像字节。依赖锁也不替代漏洞审查或数据恢复验收。

回滚采用旧代码提交及其配套锁/镜像，重建独立环境；业务数据按[发布验收与恢复流程](RELEASE_ACCEPTANCE.md)处理。不要只回退 `.in` 而留下新锁，不要将旧版对照锁用于生产。本项不改变 schema 5、业务 API 或 Agent/helper 协议。

实现依据：[uv 锁定与约束文档](https://docs.astral.sh/uv/pip/compile/)、[pip 哈希安装说明](https://pip.pypa.io/en/stable/topics/secure-installs/)。
