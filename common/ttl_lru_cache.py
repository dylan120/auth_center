"""
带 TTL 和 LRU 的缓存实现。
支持最大容量（LRU 驱逐）和单条目过期（TTL）。
线程安全。
"""

import functools
import threading
import time
from collections import OrderedDict
from collections.abc import Hashable
from typing import Any, Callable, Dict, Optional, Tuple


class TTLLRUCache:
    """带 TTL 和 LRU 驱逐机制的缓存类"""

    def __init__(self, maxsize: int = 128, ttl: int = 300) -> None:
        """
        初始化缓存

        Args:
            maxsize: 最大缓存条目数
            ttl: 缓存条目的生存时间（秒）
        """
        self.maxsize = max(maxsize, 0)
        self.ttl = ttl
        self.cache: Dict[Hashable, Tuple[Any, float]] = {}  # key -> (value, timestamp)
        self.lru_order = OrderedDict()  # key -> None (维护访问顺序)
        self.lock = threading.RLock()  # 使用可重入锁，避免死锁
        self.hits = 0
        self.misses = 0

    def get(self, key: Hashable) -> Optional[Any]:
        """
        从缓存中获取值

        Args:
            key: 缓存键

        Returns:
            缓存值，如果不存在或已过期则返回 None
        """
        if self.maxsize == 0:
            return None
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None

            value, timestamp = self.cache[key]
            # 检查是否过期
            if time.time() - timestamp > self.ttl:
                # 过期了，删除它
                self._delete(key)
                self.misses += 1
                return None

            # 更新 LRU 顺序
            self._move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: Hashable, value: Any) -> None:
        """
        设置缓存值

        Args:
            key: 缓存键
            value: 缓存值
        """
        if self.maxsize == 0:
            return None
        with self.lock:
            # 如果键已存在，更新值和时间戳
            if key in self.cache:
                self.cache[key] = (value, time.time())
                self._move_to_end(key)
                return

            # 如果缓存已满，移除最久未使用的条目
            if len(self.cache) >= self.maxsize:
                self._evict()

            # 添加新条目
            self.cache[key] = (value, time.time())
            self.lru_order[key] = None
            # 确保新条目在 LRU 顺序的末尾
            self._move_to_end(key)

    def _delete(self, key: Hashable) -> None:
        """删除一个键"""
        if key in self.cache:
            del self.cache[key]
        if key in self.lru_order:
            del self.lru_order[key]

    def _move_to_end(self, key: Hashable) -> None:
        """将键移动到 LRU 顺序末尾（表示最近使用）"""
        if key in self.lru_order:
            self.lru_order.move_to_end(key)

    def _evict(self) -> None:
        """移除最久未使用的条目"""
        if self.lru_order:
            oldest_key = next(iter(self.lru_order))
            self._delete(oldest_key)

    def cache_info(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        with self.lock:
            return {
                "hits": self.hits,
                "misses": self.misses,
                "maxsize": self.maxsize,
                "currsize": len(self.cache),
                "hit_rate": self.hits / (self.hits + self.misses)
                if (self.hits + self.misses) > 0
                else 0,
            }

    def cache_clear(self) -> None:
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.lru_order.clear()
            self.hits = 0
            self.misses = 0

    def __contains__(self, key: Hashable) -> bool:
        """检查键是否在缓存中（不考虑过期）"""
        with self.lock:
            return key in self.cache

    def __len__(self) -> int:
        """返回缓存中的条目数"""
        with self.lock:
            return len(self.cache)


def ttl_lru_cache(maxsize: int = 128, ttl: int = 300) -> Callable:
    """
    带 TTL 和 LRU 的缓存装饰器

    Args:
        maxsize: 最大缓存条目数
        ttl: 缓存条目的生存时间（秒）

    Returns:
        装饰器函数
    """

    def decorator(func: Callable) -> Callable:
        cache = TTLLRUCache(maxsize=maxsize, ttl=ttl)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 生成缓存键
            key = _make_key(args, kwargs)

            # 尝试从缓存获取
            result = cache.get(key)
            if result is not None:
                return result

            # 缓存未命中，调用原函数
            result = func(*args, **kwargs)

            # 存入缓存
            cache.set(key, result)
            return result

        # 暴露缓存管理方法
        wrapper.cache_info = cache.cache_info
        wrapper.cache_clear = cache.cache_clear
        wrapper.cache = cache  # 暴露缓存实例以便高级操作

        return wrapper

    return decorator


def _make_key(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Hashable:
    """
    生成缓存键 —— 改进版，支持 list, dict, set 等不可哈希类型

    Args:
        args: 位置参数
        kwargs: 关键字参数

    Returns:
        可哈希的键
    """
    # 递归转换 args
    hashable_args = tuple(_make_hashable(arg) for arg in args)

    # 递归转换 kwargs（保持键有序）
    sorted_kwargs = tuple(
        sorted((key, _make_hashable(value)) for key, value in kwargs.items())
    )

    return (hashable_args, sorted_kwargs)


def _make_hashable(obj: Any) -> Hashable:
    """
    递归将对象转换为可哈希形式
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, list):
        return tuple(_make_hashable(item) for item in obj)
    elif isinstance(obj, set):
        return frozenset(_make_hashable(item) for item in obj)
    elif isinstance(obj, dict):
        return frozenset((key, _make_hashable(value)) for key, value in obj.items())
    elif isinstance(obj, tuple):
        return tuple(_make_hashable(item) for item in obj)
    else:
        # 对于自定义对象，尝试直接哈希；失败则用 repr（最后手段）
        result: Hashable = None
        try:
            result = hash(obj)
        except TypeError:
            # 转字符串（可能冲突，但保证可哈希）
            result = repr(obj)
        return result


# 示例使用
if __name__ == "__main__":
    # 使用装饰器
    @ttl_lru_cache(maxsize=10, ttl=60)
    def expensive_function(x: int, y: int = 0) -> int:
        """expensive_function"""
        print(f"Computing {x} + {y}...")
        return x + y

    # 测试
    print(expensive_function(1, 2))  # 计算并缓存
    print(expensive_function(1, 2))  # 从缓存获取
    print(expensive_function.cache_info())  # 查看缓存统计
