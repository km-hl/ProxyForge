# 中文说明索引与覆盖表

核对日期：2026-10-08。范围为受 Git 跟踪的根 README、Agent README、docs 全部说明和 Mihomo 测试 README；不读取或发布本机 MEMORY.md、私有计划、运行数据与 .env。表中“中文正文”表示直接阅读原文件即可，不要求另建同名 zh-CN 副本。

本次将原英文为主的 B1/B2/B3、模板历史和 Mihomo 测试说明直接改为中文，保持原路径，涵盖原有协议、限制、测试、迁移和回滚内容。Agent 保留中英互链。协议字段、命令和第三方正式名称保留原文；固定安装产物中的英文帮助/输出另有完整中文对照，不为文字修改已审查的安装来源或 hash。

## 当前使用入口

- [Controller 部署与使用](../README.md)：安装、权限准备和更新入口。
- [Agent 完整安装命令](AGENT_INSTALL.md)：控制台复制、固定来源/hash、普通 Agent 与可选 helper、验收矩阵。
- [Agent 中文 README](../agent/README.zh-CN.md)与[安装帮助](AGENT_INSTALL_HELP.md)：参数、终端提示、恢复、升级、卸载。
- [发布验收与恢复](RELEASE_ACCEPTANCE.md)：冷备、副本恢复、切换、回滚和验证范围。
- [开发计划及进度](NEXT_STEPS.md)：已合并和未完成任务。

## 逐文件覆盖

| 文件 | 中文入口／状态 | 核对重点 |
| --- | --- | --- |
| [README.md](../README.md) | 中文正文 | 修复过期冲突描述、零延迟/更新绝对安全承诺、旧迁移路径；链接到冷备和非 root 权限流程 |
| [agent/README.md](../agent/README.md) | 顶部链接中文版本，英文保留 | 安装、凭据、可选 helper、心跳、任务、开发、卸载、历史升级与当前恢复 |
| [agent/README.zh-CN.md](../agent/README.zh-CN.md) | 完整中文，与英文互链 | 保留相同能力和恢复边界，修正“控制台入口未完成”的旧状态 |
| [AGENT_ARTIFACTS.md](AGENT_ARTIFACTS.md) | 中文正文 | Git 固定产物、manifest/hash、工具用法与分发边界；新增帮助加入固定文档清单 |
| [AGENT_INSTALL.md](AGENT_INSTALL.md) | 中文正文 | 三份完整固定命令、可信地址配置、API、失败恢复与实测矩阵 |
| [AGENT_INSTALL_HELP.md](AGENT_INSTALL_HELP.md) | 新增中文对照 | 脚本/Agent 参数、隐藏凭据、全部安装固定提示及 wrapper 错误 |
| [AGENT_B1.md](AGENT_B1.md) | 本次补齐中文正文 | 清单表、API、鉴权、状态、备份/回滚；schema 1 为历史 |
| [AGENT_B2.md](AGENT_B2.md) | 本次补齐中文正文 | 队列、租约、幂等/重放边界、日志、迁移/回滚；schema 2 为历史 |
| [AGENT_B3.md](AGENT_B3.md) | 本次补齐中文正文 | helper 权限、固定下载、续租、代际事务、备份/回滚；B3 无低端口是历史 |
| [AGENT_B4.md](AGENT_B4.md) | 中文正文，补历史提示 | Reality、加密、节点归属、schema 3 与低端口能力 |
| [AGENT_B5_LANDING.md](AGENT_B5_LANDING.md) | 中文正文，补历史提示 | SS2022、schema 4、密码保管、TCP/UDP 验收及恢复 |
| [AGENT_B5_CHAIN.md](AGENT_B5_CHAIN.md) | 中文正文，补历史提示 | schema 5、入口/落地依赖、链路快照、发布和恢复 |
| [AGENT_B6_NODES_UI.md](AGENT_B6_NODES_UI.md) | 中文正文 | 托管清单/API、状态与发布资格、管理归属、无迁移升级 |
| [AIRPORT_BACKGROUND.md](AIRPORT_BACKGROUND.md) | 中文正文 | 线程刷新、启动/关闭、取消与停止后提交边界 |
| [AIRPORT_CACHE_ATOMIC.md](AIRPORT_CACHE_ATOMIC.md) | 中文正文 | 原子写、提交前后失败、临时文件与平台差异 |
| [AIRPORT_CACHE_CONCURRENCY.md](AIRPORT_CACHE_CONCURRENCY.md) | 中文正文 | 代次、来源快照、锁顺序、单进程边界 |
| [AIRPORT_INFO_CACHE.md](AIRPORT_INFO_CACHE.md) | 中文正文 | 批次增量、刷新优先级、旧数据兼容与失败 |
| [CONTAINER_PERMISSIONS.md](CONTAINER_PERMISSIONS.md) | 中文正文 | 10001:10001、首启/旧数据迁移、权限拒绝及回滚 |
| [DEPENDENCIES.md](DEPENDENCIES.md) | 中文正文 | 完整依赖/hash、镜像 digest、重生成和平台边界 |
| [PYTHON_RUNTIME.md](PYTHON_RUNTIME.md) | 中文正文 | Controller/Agent 独立矩阵、升级和冷恢复 |
| [OUTBOUND_HTTP.md](OUTBOUND_HTTP.md) | 中文正文 | Session、DNS pinning、TLS、显式 CA、兼容性 |
| [OUTBOUND_BUDGETS.md](OUTBOUND_BUDGETS.md) | 中文正文 | 请求/批次预算、DNS/慢流、缓存与退出边界 |
| [TEMPLATE_REVISIONS.md](TEMPLATE_REVISIONS.md) | 本次补齐中文正文 | optimistic revision、历史、redo 提交点、冲突/恢复 API |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | 中文正文 | 包职责、导入副作用、工具、测试与升级/回滚 |
| [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md) | 中文正文 | 发布门禁、冷备、Agent/controller 顺序、迁移与回滚 |
| [NEXT_STEPS.md](NEXT_STEPS.md) | 中文正文，更新合并状态 | 原始历史依据与当前完成/待验收清单分开 |
| [tests/mihomo/README.md](../tests/mihomo/README.md) | 本次补齐中文正文 | 下载/生成/解析命令、网络隔离、静态差异与未覆盖范围 |
| [DOCUMENTATION.md](DOCUMENTATION.md) | 本文 | 完整索引与后续维护要求 |
| [EGERN_EXPORT.md](EGERN_EXPORT.md) | 中文正文 | Egern 原生订阅、规则资源、兼容边界、鉴权、验证与恢复 |

## 核验方式与持续维护

本次逐节对照原英文内容检查协议字段、数值限制、路径、命令、异常、迁移和回滚，而不是根据汉字数量判断翻译完整。核对本地相对链接、代码块围栏、Bash 示例语法，检查固定安装命令与生成器/hash 一致，并运行隐私和 diff 检查。文档核验不执行生产命令，不增加或宣称运行时/公网验收。

每个改变用户行为的 PR 同步中文说明；保留英文版本时顶部互链且信息对等。增加/删除说明文件时更新本表。历史阶段记录须标出适用版本，当前操作统一指向安装/发布指南。安装参数标识符不翻译，但其用途和故障恢复须有中文入口。第三方源码、许可证和权威规范保持原文，中文解释不替代正式条款；未来 Release notes 同样须提供完整中文内容。

本次文档补齐不代表第 16 项所有安装平台或公网验收完成，也不代表已选择许可证、发布正式 Release 或部署生产；这些状态以[开发计划](NEXT_STEPS.md)和对应发布记录为准。

| [AGENT_INSTALL_DEBIAN_CI.md](AGENT_INSTALL_DEBIAN_CI.md) | 中文正文 | Debian 同架构 systemd 容器、固定镜像、特权 CI 范围及 VM/公网边界 |
