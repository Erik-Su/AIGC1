from __future__ import annotations

import importlib
from types import ModuleType

from fastapi.testclient import TestClient
import pytest

from app.main import create_app

class EnvTestBase:
    """关于环境的测试基类
    
    """
    def set_env(self, monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> None:
        for key, value in values.items():
            monkeypatch.setenv(key, value)

    def reload_modules(self, *modules: ModuleType) -> tuple[ModuleType, ...]:
        return tuple(importlib.reload(module) for module in modules)
    

class ApiTestBase:
    """关于API接口的测试基类

    """
    def create_client(self) -> TestClient:
        return TestClient(create_app())


class FakeRedis:
    """测试用内存 Redis，替代真实 Redis 连接，避免测试依赖 Redis 服务。"""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)