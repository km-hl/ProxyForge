# 机场缓存原子写入

本文对应[开发计划](NEXT_STEPS.md)第 3 项，覆盖 `data/airport_cache.yaml` 和 `data/airports_info_cache.json`。
缓存格式、路径、节点回退、24 小时机场信息期限及 `force_indices` 行为保持不变，无需数据库或 Agent 升级。

## 实现与接口

两个缓存写入口先在内存中完成 YAML/JSON 序列化，再复用 `proxyforge/config/template_store.py` 的 `atomic_write(path, content)`：

1. 在目标文件同一目录创建独占、随机命名的临时文件，POSIX 权限为 0600。
2. 写入完整内容，flush 并 fsync 文件。
3. 用 `os.replace` 替换目标路径，在支持的平台上同步父目录。
4. 常规退出和可处理异常时清理本次临时文件。

节点入口仍为 `save_cache_to_file(proxies, snapshot)`，保留[来源快照和失效代次检查](AIRPORT_CACHE_CONCURRENCY.md)，`/sub` 与后台刷新都通过该入口提交。
第 3 项最初替换 `fetch_single_airport_info` 的 JSON 落盘方式；后续第 2 项已将其移至请求汇总层的 `save_airport_info_cache(data)`，worker 只请求与解析。详见[机场信息缓存](AIRPORT_INFO_CACHE.md)。缓存不进入模板历史，也不新增模板事务文件。

磁盘失败不取消已经获得的节点/机场信息。日志只记录固定描述和异常类型，不包含原始异常中的路径、URL、订阅内容或凭据。

## 故障保证与边界

| 故障阶段 | 文件状态 |
| --- | --- |
| 序列化、写临时文件、flush、文件 fsync 或 replace 失败 | 原文件保持完整；若原先不存在，目标路径仍不存在。常规异常清理临时文件。 |
| replace 成功后目录 fsync 失败 | 目标已是完整新文件，持久化结果未确认；不能声称旧文件仍在。记录写失败，返回已获得的数据。 |
| 进程在 replace 前被强制终止 | 应用仍读取旧文件；可能留下以点开头的临时文件。`finally` 无法保证执行。 |

同目录替换避免跨文件系统移动；读取者只打开正式文件名，不扫描或读取临时文件。Windows 不执行 POSIX 目录 fsync，0600 也不能替代 Windows ACL，不能把 Linux 持久化/权限保证无条件延伸到其他平台。

原子替换只保证单文件完整性，不保证两个缓存同时提交；多个机场信息 worker 覆盖结果的问题已由后续第 2 项的汇总与跨请求提交解决。后台线程化和关闭管理已由后续第 1 项实现，详见[后台刷新说明](AIRPORT_BACKGROUND.md)。

## 中断残留清理

不在线自动扫描删除临时文件，以免删除活跃 writer。通常异常由工具的 `finally` 清理。
如果强制终止后需要清理，先停止 Controller 并确认没有使用该目录的 writer，核对文件位于实际 `data/` 内且名称为 `.airport_cache.yaml.<32位十六进制标识>` 或 `.airports_info_cache.json.<32位十六进制标识>`，再删除核实过的具体路径。
不要递归删除 `data/`、使用覆盖所有点文件的通配符，或碰模板事务、数据库、密钥和其他缓存文件。临时文件可能包含节点凭据/订阅地址，不能上传排障。

## 验证

`tests/test_airport_atomic.py` 直接调用隔离的生产应用，覆盖两个格式的序列化中断、部分写入、flush、fsync、replace 与目录同步失败、读者在替换前后看到完整内容、错误脱敏、缓存命中/强制刷新兼容，以及 POSIX 文件权限。
另使用独立子进程执行真实缓存写入，在文件同步后、替换前终止该进程，确认旧文件不变，残留与正式路径隔离，且停写后可以按确切路径安全清理。
所有故障只注入临时测试目录，不访问生产数据。

## 升级与回滚

升级/回滚完整 Controller 代码或镜像即可，不恢复旧缓存、不修改 DB schema 或凭据。旧格式继续可读。
回滚会重新引入截断/半写风险。本项属于 P0 的中间步骤，待完整 P0 验收后再部署。
