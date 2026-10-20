# 许可证与第三方归属

## 项目许可

所有者于 2026-10-20 确认 ProxyForge 自有代码及文档采用 MIT；正式条款见根目录 [LICENSE](../LICENSE)。英文许可正文保留权威文本，本说明提供中文入口，不替换原条款。允许使用、复制、修改及分发，须保留版权和许可声明；软件按原样提供，不提供担保。规范文本见 [OSI MIT](https://opensource.org/license/mit) 与 [SPDX MIT](https://spdx.org/licenses/MIT.html)。

根 LICENSE 与 [Agent 许可副本](../agent/LICENSE) 必须相同。完整 Git 源码和 Controller 镜像保留根 LICENSE；当前源码安装和最小 Agent 包保留 agent/LICENSE，安装到 `/opt/proxyforge-agent/agent/LICENSE`。历史固定 bootstrap 继续使用原先经过校验的源码，当前未推进下载锚点；正式发布时须另核对并推进安装来源，不能把历史安装说成已安装当前源码。

MIT 只声明本项目自有部分的许可，以下第三方组件、图形、运行时及其依赖继续使用各自条款，不因本项目新增 LICENSE 改为 MIT。此说明不将协议兼容、外部链接或进程调用等同于取得第三方重新许可权。

## 浏览器依赖与图形

| 组件 | 目前使用版本/方式 | 上游归属与条款 |
| --- | --- | --- |
| js-yaml | 4.1.0，固定 CDN URL 与 SRI，未将脚本源码收入仓库 | Vitaly Puzrin；[版本许可 MIT](https://github.com/nodeca/js-yaml/blob/4.1.0/LICENSE) |
| @twemoji/api | 14.1.0，固定 CDN URL 与 SRI | Twitter / Twemoji contributors；代码为 [MIT](https://cdn.jsdelivr.net/npm/@twemoji/api@14.1.0/LICENSE)，[版本元数据](https://www.npmjs.com/package/@twemoji/api/v/14.1.0) 声明 MIT AND CC-BY-4.0 |
| Twemoji emoji 图形 | 上述 API 解析国旗时使用的上游资源，未修改图形 | Twitter / Twemoji contributors；[CC-BY-4.0 正文](https://cdn.jsdelivr.net/npm/@twemoji/api@14.1.0/LICENSE-GRAPHICS)，归属为 Twemoji，源项目 [jdecked/twemoji](https://github.com/jdecked/twemoji) |

将来本地镜像、修改或重新分发上述脚本/图形时，须一并保留相应许可、归属和变更说明；本表不代替所分发副本自己的 LICENSE/NOTICE。

## Controller Python 生产依赖

以下为当前 requirements.txt 的 24 个锁定包，按实际安装 wheel 的 License-Expression/License 与随包许可核对。Python 包安装保留各自 dist-info 中的许可文件；重新打包时不能仅复制本项目 LICENSE 而移除这些文件。锁文件更新后同步复核，表格不是运行时动态依赖解析。

| 包 | 锁定版本 | 上游声明许可 |
| --- | --- | --- |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| cachetools | 7.2.0 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| cryptography | 46.0.5 | Apache-2.0 OR BSD-3-Clause |
| fastapi | 0.142.2 | MIT |
| h11 | 0.16.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| opentelemetry-api | 1.45.0 | Apache-2.0 |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| pyyaml | 6.0.3 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| starlette | 1.7.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |

cryptography 的 wheel 还包含编译依赖的许可归属，应保留随 wheel 提供的许可材料；“Apache-2.0 OR BSD-3-Clause”不表示所有第三方组成部分都可任意改为 MIT。Python 运行时及 Debian 基础镜像也有各自许可文件，镜像分发保留其现有声明，本项目不覆盖它们。

## 外部订阅与规则数据

机场订阅、用户节点配置和规则数据不属于本项目 MIT 声明的自有代码。Egern 地理规则默认按请求读取 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，该仓库声明 [GPL v3](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)，并汇集其他上游数据；分发转换结果时仍需核对实际数据来源、版本及其归属。用户配置的 rule-provider/airport 来源也保留各自条款。本项目源码/最小 Agent 包不打包这些实时数据，不将下载和转换视为重新许可。

## 可选外部内核与测试工具

| 项目 | 固定版本 | 使用及许可边界 |
| --- | --- | --- |
| sing-box | 1.14.2 | helper 明确启用后按固定哈希下载，独立进程运行；[该版本许可](https://github.com/SagerNet/sing-box/blob/v1.14.2/LICENSE) 为 GPL v3 或更高版本，并包含名称/关联声明限制。官方源码和发行内容以 [SagerNet/sing-box](https://github.com/SagerNet/sing-box/tree/v1.14.2) 为准 |
| Mihomo | v1.19.31 | CI/本地兼容测试独立下载使用，不加入最小 Agent 包；[版本许可 GPL v3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/LICENSE)，源码见 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/tree/v1.19.31) |

当前最小 Agent 包只含本项目 Agent 代码/许可与选定说明，不打包 sing-box、Mihomo 或 Python 第三方 wheel。若未来镜像、离线包或 Release 附件携带外部二进制，发布前必须根据该版本的实际副本保留 LICENSE/NOTICE，并核对相应源码提供义务；不能用本项目 MIT 文本替代这些材料。项目名称不表示获得上述上游的背书。
