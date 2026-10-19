"""内部来源快照：兼容旧字符串/对象，不负责外部校验或磁盘重写。"""
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Tuple

from proxyforge.subscription.nodes import get_airport_name


@dataclass(frozen=True)
class AirportSource:
    """保留位置与完整原始值；公开投影不暴露内部可变对象。

    url 用于节点请求；info_url/info_alias 刻意沿用元信息旧规则。
    URL 安全校验仍在 API 和实际 HTTP client 中执行，不在此隐式联网。
    原始来源不进入 repr，避免异常诊断输出订阅凭据。
    """
    index: int
    _legacy: Any = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self, '_legacy', deepcopy(self._legacy))

    @classmethod
    def from_legacy(cls, value: Any, index: int = 0) -> 'AirportSource':
        return value if isinstance(value, cls) else cls(index, value)

    def to_legacy(self) -> Any:
        return deepcopy(self._legacy)

    @property
    def _url_value(self) -> Any:
        return self._legacy.get('url', '') if isinstance(self._legacy, dict) else self._legacy

    @property
    def url(self) -> Optional[str]:
        value = self._url_value
        return (value.strip() or None) if isinstance(value, str) else None

    @property
    def name(self) -> str:
        return get_airport_name(self._legacy, self.index)

    @property
    def info_url(self) -> str:
        # 不将错误类型强制转成 URL，沿用旧配置在元信息读取时的失败边界。
        return self._url_value.strip()

    @property
    def info_alias(self) -> Any:
        # 外部 API 尚未收紧 name 类型；空白别名也不能偷偷 trim。
        return deepcopy(self._legacy.get('name', '')) if isinstance(self._legacy, dict) else ''


def normalize_sources(values: Iterable[Any]) -> Tuple[AirportSource, ...]:
    """只建立内存视图；保留顺序、重复 URL 和所有未知扩展字段。"""
    return tuple(AirportSource.from_legacy(item, index) for index, item in enumerate(values))


@dataclass(frozen=True)
class AirportSnapshot:
    sources: Tuple[AirportSource, ...]
    generation: int

    def to_legacy(self) -> list:
        return [source.to_legacy() for source in self.sources]
