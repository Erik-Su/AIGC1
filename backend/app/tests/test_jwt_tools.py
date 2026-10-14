from __future__ import annotations

import pytest

from app.core import database as database_module
from app.tests.base import FakeRedis
from app.utils import jwt_tools


class TestJwtTools:
    def _patch_redis(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """将真实 Redis 替换为内存假对象。"""
        monkeypatch.setattr(database_module, "redis_client", FakeRedis())

    @pytest.mark.anyio
    async def test_create_login_tokens_returns_distinct_tokens(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._patch_redis(monkeypatch)

        tokens = await jwt_tools.create_login_tokens(public_id="pid-1", username="alice")

        assert tokens["access_token"]
        assert tokens["refresh_token"]
        assert tokens["access_token"] != tokens["refresh_token"]
        assert tokens["expires_in"] == jwt_tools.settings.access_token_expire_seconds

    @pytest.mark.anyio
    async def test_login_tokens_decode_to_expected_payload(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._patch_redis(monkeypatch)

        tokens = await jwt_tools.create_login_tokens(public_id="pid-1", username="alice")

        access_payload = jwt_tools.jwt.decode(
            tokens["access_token"],
            jwt_tools.settings.secret_key,
            algorithms=[jwt_tools.settings.algorithm],
        )
        assert access_payload["sub"] == "pid-1"
        assert access_payload["username"] == "alice"
        assert access_payload["type"] == "access"

        refresh_payload = jwt_tools.jwt.decode(
            tokens["refresh_token"],
            jwt_tools.settings.secret_key,
            algorithms=[jwt_tools.settings.algorithm],
        )
        assert refresh_payload["type"] == "refresh"

    @pytest.mark.anyio
    async def test_decode_token_rejects_revoked_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._patch_redis(monkeypatch)

        tokens = await jwt_tools.create_login_tokens(public_id="pid-1", username="alice")

        payload = await jwt_tools.decode_token(tokens["access_token"])
        assert payload["sub"] == "pid-1"

        await jwt_tools.revoke_token(payload["jti"])

        with pytest.raises(ValueError, match="revoked"):
            await jwt_tools.decode_token(tokens["access_token"])

    @pytest.mark.anyio
    async def test_refresh_token_creates_new_access_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._patch_redis(monkeypatch)

        tokens = await jwt_tools.create_login_tokens(public_id="pid-1", username="alice")

        refreshed = await jwt_tools.create_access_token_from_refresh_token(tokens["refresh_token"])

        assert refreshed["access_token"]
        assert refreshed["access_token"] != tokens["access_token"]
        assert refreshed["expires_in"] == jwt_tools.settings.access_token_expire_seconds

    @pytest.mark.anyio
    async def test_access_token_cannot_be_used_to_refresh(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._patch_redis(monkeypatch)

        tokens = await jwt_tools.create_login_tokens(public_id="pid-1", username="alice")

        with pytest.raises(ValueError, match="Refresh token required"):
            await jwt_tools.create_access_token_from_refresh_token(tokens["access_token"])
