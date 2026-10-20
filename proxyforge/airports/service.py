"""机场拉取、缓存及刷新协调；所有运行依赖由调用方注入。"""
import json
import logging
import os
import re
import threading
import urllib.parse
from contextlib import contextmanager
from copy import deepcopy
from functools import wraps
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import yaml
from cachetools import TTLCache
from typing import List, Dict, Any, Optional, Tuple

from proxyforge.config.template_store import atomic_write, sync_directory
from proxyforge.security.outbound_budget import check_outbound_deadline, OutboundTimeout, OutboundCancelled
from proxyforge.subscription.validation import ConfigValidationError
from .parser import parse_airport_response
from .sources import AirportSource, AirportSnapshot, normalize_sources


class AirportSourcesChanged(Exception):
    """刷新不再属于当前来源或缓存代次，由 Web 适配层映射为 503。"""


def coordinated(function):
    @wraps(function)
    def wrapper(self, *args, **kwargs):
        with self.configuration_lock():
            return function(self, *args, **kwargs)
    return wrapper


class AirportService:
    """单进程内共享实例；配置锁先于缓存锁，网络请求在锁外进行。

    sources_reader 保留旧来源格式；configuration_lock 须执行模板事务恢复，
    且可重入。clock 与 monotonic 分别用于持久时间戳和批次/TTL 截止时间。
    构造只建立内存状态，不读取来源、文件或环境，不发起网络请求。
    """
    def __init__(self, *, sources_reader, cache_path, info_cache_path, http_get,
                 clock, monotonic, configuration_lock, ca_bundle=None,
                 batch_timeout=180.0, logger=None):
        self.load_airports = sources_reader
        self.cache_path = Path(cache_path)
        self.info_cache_path = Path(info_cache_path)
        self.http_get = http_get
        self.clock = clock
        self.monotonic = monotonic
        self.configuration_lock = configuration_lock
        self.ca_bundle = ca_bundle
        self.batch_timeout = batch_timeout
        self.logger = logger if logger is not None else logging.getLogger(__name__)
        self._subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60, timer=monotonic)
        self._subscription_cache_lock = threading.RLock()
        self._airport_cache_generation = 0
        self._airport_cache_sources: Optional[Tuple[AirportSource, ...]] = None
        self._airport_info_generation = 0
        self._airport_info_sequence = 0
        self._airport_info_accepted = {}

    @coordinated
    def invalidate_airport_cache(self, *, clear_disk=False):
        with self._subscription_cache_lock:
            self._airport_cache_generation += 1
            self._subscription_cache.clear()
            if clear_disk:
                self._airport_cache_sources = None
                self._airport_info_generation += 1
                self._airport_info_accepted.clear()
                # Remove before committing changed sources: a crash must not leave a
                # name-only disk cache belonging to a different URL after restart.
                for path in (Path(self.cache_path), self.info_cache_path):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                    else:
                        sync_directory(path.parent)

    @coordinated
    def airport_cache_snapshot(self) -> AirportSnapshot:
        sources = normalize_sources(self.load_airports())
        with self._subscription_cache_lock:
            # Also notice configuration recovered from a previously committed redo
            # journal. Direct external writers are not a supported consistency API.
            if self._airport_cache_sources is not None and self._airport_cache_sources != sources:
                self.invalidate_airport_cache(clear_disk=True)
            self._airport_cache_sources = sources
            return AirportSnapshot(sources, self._airport_cache_generation)

    @contextmanager
    def airport_cache_locked(self, snapshot: AirportSnapshot):
        # Always take the configuration lock before the memory-cache lock. Never
        # perform network I/O in this context. Recovery runs before the source read.
        with self.configuration_lock():
            sources = normalize_sources(self.load_airports())
            with self._subscription_cache_lock:
                if snapshot.generation != self._airport_cache_generation or snapshot.sources != sources:
                    raise AirportSourcesChanged()
                yield

    def save_cache_to_file(self, proxies: List[Dict[str, Any]], snapshot):
        with self.airport_cache_locked(snapshot):
            try:
                content = yaml.dump(proxies, allow_unicode=True, sort_keys=False)
                atomic_write(self.cache_path, content)
            except Exception as e:
                self.logger.error("持久化节点缓存失败（%s）", type(e).__name__)

    @coordinated
    def load_cache_from_file(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.cache_path):
            return []
        # SafeLoader 的非法标量和过深嵌套不一定抛出 YAMLError。
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                nodes = yaml.safe_load(f)
                return nodes if isinstance(nodes, list) else []
        except (OSError, ValueError, yaml.YAMLError, AttributeError, KeyError, IndexError, RecursionError) as exc:
            self.logger.error("读取节点持久化缓存失败（%s）", type(exc).__name__)
        return []

    def merge_airport_proxies_with_cache(self,
        proxies: List[Dict[str, Any]], airports: List[Any]
    ):
        merged = list(proxies or [])
        cached = self.load_cache_from_file()
        available_sources = {
            str(proxy.get("_airport_name", "")).lower()
            for proxy in merged if isinstance(proxy, dict)
        }
        missing_sources = []
        for source in normalize_sources(airports):
            source_name = source.name
            source_key = source_name.lower()
            if source_key not in available_sources:
                cached_for_source = [
                    proxy for proxy in cached
                    if isinstance(proxy, dict) and str(proxy.get("_airport_name", "")).lower() == source_key
                ]
                if cached_for_source:
                    merged.extend(cached_for_source)
                    available_sources.add(source_key)
            if source_key not in available_sources:
                missing_sources.append(source_name)
        return merged, missing_sources

    def fetch_airport_item(self, item: Any, index: int = 0, *, deadline=None, stop_event=None) -> List[Dict[str, Any]]:
        source = AirportSource.from_legacy(item, index)
        url = source.url
        if url is None:
            return []

        airport_name = source.name
        source_number = source.index + 1 if type(source.index) is int and source.index >= 0 else 0
        headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
        self.logger.info(f"正在拉取机场来源 #{source_number} 的节点")
        try:
            check_outbound_deadline(deadline, stop_event)
            response = self.http_get(url, headers=headers, timeout=30, ca_bundle=self.ca_bundle,
                                     deadline=deadline, stop_event=stop_event)
            response.raise_for_status()
            proxies = parse_airport_response(response.text)
            check_outbound_deadline(deadline, stop_event)
            if proxies:
                for proxy in proxies:
                    if isinstance(proxy, dict):
                        proxy["_airport_name"] = airport_name
                self.logger.info(f"机场来源 #{source_number} 已拉取 {len(proxies)} 个节点")
                return proxies
            self.logger.warning(f"机场来源 #{source_number} 订阅内容解析成功，但未找到代理节点")
        except Exception as e:
            self.logger.error(f"机场来源 #{source_number} 拉取失败（{type(e).__name__}）")
        return []

    def fetch_airport_proxies(self, sources=None, stop_event=None) -> List[Dict[str, Any]]:
        deadline = self.monotonic() + self.batch_timeout
        urls_data = normalize_sources(self.load_airports() if sources is None else sources)
        if not urls_data:
            self.logger.warning("未配置机场订阅链接，跳过拉取。")
            return []

        def fetch(source):
            try:
                check_outbound_deadline(deadline, stop_event)
            except (OutboundTimeout, OutboundCancelled):
                return []
            return self.fetch_airport_item(source, source.index, deadline=deadline, stop_event=stop_event)

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(fetch, urls_data))

        all_proxies = []
        seen_names = set()

        for proxies in results:
            for p in proxies:
                original_name = p.get('name', 'node')
                name = original_name
                airport_name = p.get("_airport_name", "")
                collision_count = 1
                while name in seen_names:
                    name = f"{original_name} ({airport_name})"
                    if name in seen_names:
                        name = f"{original_name} ({airport_name} {collision_count})"
                        collision_count += 1
                seen_names.add(name)
                p["name"] = name
                all_proxies.append(p)

        return all_proxies

    def fetch_single_airport_info(self, item, *, deadline=None) -> dict:
        """Fetch and parse only; the caller owns all cache reads and writes."""
        source = AirportSource.from_legacy(item)
        url = source.info_url
        custom_name = source.info_alias

        info = {
            "url": url,
            "name": custom_name or urllib.parse.urlparse(url).netloc,
            "nodesCount": 0,
            "upload": 0,
            "download": 0,
            "total": 0,
            "expire": 0,
            "error": None
        }
        if not url: return info

        try:
            check_outbound_deadline(deadline)
            headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
            res = self.http_get(url, headers=headers, timeout=30, ca_bundle=self.ca_bundle, deadline=deadline)
            res.raise_for_status()

            # 尝试提取名称
            if not custom_name:
                cd = res.headers.get("content-disposition", "")
                if "filename=" in cd:
                    m = re.search(r'filename=["\']?([^"\';]+)', cd)
                    if m:
                        info["name"] = urllib.parse.unquote(m.group(1))

            # 尝试提取流量信息
            userinfo = res.headers.get("subscription-userinfo", "")
            if userinfo:
                for k in ["upload", "download", "total", "expire"]:
                    m = re.search(rf'{k}\s*=\s*(\d+)', userinfo)
                    if m:
                        info[k] = int(m.group(1))

            proxies = parse_airport_response(res.text)
            check_outbound_deadline(deadline)
            info["nodesCount"] = len(proxies)

        except Exception as e:
            info["error"] = type(e).__name__

        info["_timestamp"] = self.clock()
        return info

    @coordinated
    def load_airport_info_cache(self):
        try:
            with open(self.info_cache_path, encoding="utf-8") as stream:
                data = json.load(stream)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            self.logger.warning("读取机场信息缓存失败（%s）", type(exc).__name__)
            return {}
        if not isinstance(data, dict):
            self.logger.warning("机场信息缓存结构无效，重新获取")
            return {}
        valid = {}
        now = self.clock()
        for url, entry in data.items():
            if not isinstance(entry, dict):
                continue
            stamp, info = entry.get("_timestamp"), entry.get("info")
            if (type(stamp) not in (int, float) or not 0 <= stamp <= now
                    or not isinstance(info, dict) or info.get("url") != url
                    or not isinstance(info.get("name"), str)
                    or "error" not in info or not (info["error"] is None or isinstance(info["error"], str))
                    or any(type(info.get(field)) is not int or info[field] < 0
                           for field in ("nodesCount", "upload", "download", "total", "expire"))):
                continue
            info["_timestamp"] = stamp
            valid[url] = entry
        if len(valid) != len(data):
            self.logger.warning("机场信息缓存包含无效条目，忽略损坏条目")
        return valid

    @coordinated
    def save_airport_info_cache(self, data):
        try:
            atomic_write(self.info_cache_path, json.dumps(data))
        except Exception as exc:
            self.logger.warning("持久化机场信息缓存失败（%s）", type(exc).__name__)

    def get_airport_proxies_cached(self, snapshot=None) -> List[Dict[str, Any]]:
        if snapshot is None:
            for _ in range(2):
                try:
                    return self.get_airport_proxies_cached(self.airport_cache_snapshot())
                except AirportSourcesChanged:
                    continue
            raise AirportSourcesChanged()
        with self.airport_cache_locked(snapshot):
            cached = self._subscription_cache.get(())
            if cached is not None:
                return deepcopy(cached)
        proxies = self.fetch_airport_proxies(snapshot.sources)
        with self.airport_cache_locked(snapshot):
            # Another request may have filled the same generation while we fetched.
            cached = self._subscription_cache.get(())
            if cached is None:
                cached = deepcopy(proxies)
                self._subscription_cache[()] = cached
            return deepcopy(cached)

    def subscription_airports(self):
        for _ in range(2):
            snapshot = self.airport_cache_snapshot()
            try:
                try:
                    proxies = self.get_airport_proxies_cached(snapshot)
                except AirportSourcesChanged:
                    raise
                except Exception as exc:
                    self.logger.error("尝试使用本地持久化备份（%s）", type(exc).__name__)
                    with self.airport_cache_locked(snapshot):
                        proxies = self.load_cache_from_file()
                with self.airport_cache_locked(snapshot):
                    proxies, missing = self.merge_airport_proxies_with_cache(proxies, snapshot.sources)
                    if missing:
                        raise ConfigValidationError([
                            f"机场 [{source}] 当前未拉取到节点，且没有可用缓存" for source in missing
                        ])
                    if proxies:
                        self.save_cache_to_file(proxies, snapshot)
                    return snapshot.to_legacy(), proxies
            except AirportSourcesChanged:
                continue
        raise AirportSourcesChanged()

    def get_airports_info(self, force_indices: str = ""):
        deadline = self.monotonic() + self.batch_timeout
        force_idx_list = []
        if force_indices:
            try:
                force_idx_list = [int(x) for x in force_indices.split(",") if x.strip()]
            except ValueError:
                pass

        for _ in range(2):
            with self.configuration_lock():
                sources = normalize_sources(self.load_airports())
                generation = self._airport_info_generation
                self._airport_info_sequence += 1
                sequence = self._airport_info_sequence
                cached = self.load_airport_info_cache()
                urls = [source.info_url for source in sources]
                force_urls = {url for i, url in enumerate(urls) if i in force_idx_list or force_indices == "all"}
                now = self.clock()
                pending = list(dict.fromkeys(url for url in urls if url in force_urls or url not in cached
                                             or now - cached[url]["_timestamp"] >= 24 * 3600))

            # One fetch per URL, independent of aliases. No configuration/cache lock
            # is held during network I/O and workers never touch shared cache files.
            with ThreadPoolExecutor(max_workers=5) as executor:
                fetched = dict(zip(pending, executor.map(lambda item: self.fetch_single_airport_info(item, deadline=deadline), pending)))

            with self.configuration_lock():
                if generation != self._airport_info_generation or sources != normalize_sources(self.load_airports()):
                    continue
                latest = self.load_airport_info_cache()
                # Re-read and merge only this request's fresh entries. A newer
                # accepted refresh wins even if its replace/directory fsync failed.
                entries = {url: value for url, value in latest.items() if url in urls}
                changed = False
                for url, info in fetched.items():
                    if url and sequence > self._airport_info_accepted.get(url, 0):
                        entries[url] = {"info": info, "_timestamp": info["_timestamp"]}
                        self._airport_info_accepted[url] = sequence
                        changed = True
                if changed:
                    self.save_airport_info_cache(entries)
                results = []
                for source, url in zip(sources, urls):
                    # Prefer a concurrent committed refresh; if persistence failed,
                    # still return the result acquired by this request.
                    if url in fetched and self._airport_info_accepted.get(url) == sequence:
                        info = fetched[url]
                    elif url in entries:
                        info = entries[url]["info"]
                    elif url in fetched:
                        info = fetched[url]
                    else:
                        info = cached[url]["info"]
                    info = deepcopy(info)
                    if source.info_alias:
                        info["name"] = source.info_alias
                    results.append(info)
                return {"info": results}
        raise AirportSourcesChanged()

    def refresh_airport_cache(self, stop_event=None):
        def stopping():
            return stop_event is not None and stop_event.is_set()

        if stopping():
            return
        snapshot = self.airport_cache_snapshot()
        if stopping():
            return
        proxies = self.fetch_airport_proxies(snapshot.sources, stop_event=stop_event)
        if stopping():
            return
        try:
            with self.airport_cache_locked(snapshot):
                proxies, missing_sources = self.merge_airport_proxies_with_cache(proxies, snapshot.sources)
                # Check again after waiting for the configuration lock and disk I/O.
                if stopping():
                    return
                if proxies and not missing_sources:
                    self.save_cache_to_file(proxies, snapshot)
                    # Supersede in-flight foreground computations as well as the
                    # previous cached value, without changing the source list.
                    self.invalidate_airport_cache()
                    self._subscription_cache[()] = deepcopy(proxies)
                    self.logger.info("后台定时任务完成，成功更新了 %s 个机场节点", len(proxies))
                else:
                    self.logger.warning("后台定时任务：机场数据不完整，放弃覆盖旧缓存")
        except AirportSourcesChanged:
            self.logger.info("后台定时任务：来源已更新，丢弃旧刷新结果")
