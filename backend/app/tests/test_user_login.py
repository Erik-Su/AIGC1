from __future__ import annotations

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from app import main as main_module
from app.core import config as config_module
from app.core import database as database_module
from app.routers import api as api_module
from app.routers import user as user_router_module
from app.schemas.user import UserCreate
from app.services import user as user_service_module
from app.tests.base import EnvTestBase, FakeRedis


class TestUserLogin(EnvTestBase):
    async def _prepare(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> tuple:
        """配置 SQLite 环境、用内存 Redis 替换真实连接，并创建应用与数据表。"""
        self.set_env(
            monkeypatch,
            {
                "DB_ENGINE": "sqlite",
                "DB_DRIVER": "aiosqlite",
                "DB_SQLITE_PATH": str(tmp_path / "login.db"),
            },
        )

        _, database, user_service, _, _, main = self.reload_modules(
            config_module,
            database_module,
            user_service_module,
            user_router_module,
            api_module,
            main_module,
        )
        # 登录流程会向 Redis 写入 token，用内存假对象避免依赖真实 Redis 服务。
        monkeypatch.setattr(database, "redis_client", FakeRedis())

        app = main.create_app()
        await database.create_db_and_tables()
        return database, app, user_service

    async def _create_user(
        self,
        database,
        user_service,
        username: str,
        password: str,
    ) -> dict:
        """通过服务层直接创建用户，绕开受鉴权保护的创建接口。"""
        async with database.async_session_maker() as session:
            user = await user_service.create_user(
                session,
                UserCreate(
                    username=username,
                    nickname=username.title(),
                    email=f"{username}@example.com",
                    password=password,
                    repassword=password,
                ),
            )
        return {
            "public_id": user.public_id,
            "username": user.username,
            "nickname": user.nickname,
        }

    @pytest.mark.anyio
    async def test_login_success_returns_tokens_and_user_info(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")
                response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "password123"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["access_token"] != body["refresh_token"]
        assert body["expires_in"] == config_module.settings.access_token_expire_seconds
        assert body["user"]["public_id"] == created["public_id"]
        assert body["user"]["username"] == "moluo"
        assert body["user"]["nickname"] == "Moluo"

    @pytest.mark.anyio
    async def test_login_tokens_are_valid_jwt(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")
                response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "password123"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 200
        body = response.json()

        access_payload = jwt.decode(
            body["access_token"],
            config_module.settings.secret_key,
            algorithms=[config_module.settings.algorithm],
        )
        assert access_payload["sub"] == created["public_id"]
        assert access_payload["username"] == "moluo"
        assert access_payload["type"] == "access"

        refresh_payload = jwt.decode(
            body["refresh_token"],
            config_module.settings.secret_key,
            algorithms=[config_module.settings.algorithm],
        )
        assert refresh_payload["type"] == "refresh"

    @pytest.mark.anyio
    async def test_login_unknown_username_returns_401(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, _ = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                response = await client.post(
                    "/api/users/login",
                    json={"username": "ghost", "password": "password123"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401
        assert response.json()["detail"] == "用户名或密码错误"

    @pytest.mark.anyio
    async def test_login_wrong_password_returns_401(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                await self._create_user(database, user_service, "moluo", "password123")
                response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "wrongpassword"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401
        assert response.json()["detail"] == "用户名或密码错误"

    @pytest.mark.anyio
    async def test_login_disabled_user_returns_403(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")
                async with database.async_session_maker() as session:
                    await user_service.disable_user(session, created["public_id"])

                response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "password123"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 403
        assert response.json()["detail"] == "用户已被禁用"

    @pytest.mark.anyio
    async def test_login_updates_last_login_at(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")

                async with database.async_session_maker() as session:
                    before = await user_service.get_user_by_public_id(session, created["public_id"])
                    assert before.last_login_at is None

                await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "password123"},
                )

                async with database.async_session_maker() as session:
                    after = await user_service.get_user_by_public_id(session, created["public_id"])
                    assert after.last_login_at is not None
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

    @pytest.mark.anyio
    async def test_login_short_password_returns_422(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, _ = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "short"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 422

    @pytest.mark.anyio
    async def test_login_missing_username_returns_422(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, _ = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                response = await client.post(
                    "/api/users/login",
                    json={"password": "password123"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 422

    @pytest.mark.anyio
    async def test_login_token_grants_access_to_protected_endpoint(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")
                login_response = await client.post(
                    "/api/users/login",
                    json={"username": "moluo", "password": "password123"},
                )
                access_token = login_response.json()["access_token"]

                list_response = await client.get(
                    "/api/users/",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert list_response.status_code == 200
        assert created["username"] in [user["username"] for user in list_response.json()]

    @pytest.mark.anyio
    async def test_protected_endpoint_requires_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, _ = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                response = await client.get("/api/users/")
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401

    async def _login(self, client: AsyncClient) -> dict:
        """以固定账号登录并返回响应体。"""
        response = await client.post(
            "/api/users/login",
            json={"username": "moluo", "password": "password123"},
        )
        return response.json()

    @pytest.mark.anyio
    async def test_refresh_token_returns_usable_access_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                await self._create_user(database, user_service, "moluo", "password123")
                login_body = await self._login(client)
                refresh_response = await client.post(
                    "/api/users/refresh-token",
                    json={"refresh_token": login_body["refresh_token"]},
                )
                new_access_token = refresh_response.json().get("access_token", "")
                me_response = await client.get(
                    "/api/users/me",
                    headers={"Authorization": f"Bearer {new_access_token}"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert refresh_response.status_code == 200
        body = refresh_response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] != login_body["access_token"]
        assert body["expires_in"] == config_module.settings.access_token_expire_seconds
        assert me_response.status_code == 200

    @pytest.mark.anyio
    async def test_refresh_token_rejects_access_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                await self._create_user(database, user_service, "moluo", "password123")
                login_body = await self._login(client)
                response = await client.post(
                    "/api/users/refresh-token",
                    json={"refresh_token": login_body["access_token"]},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401

    @pytest.mark.anyio
    async def test_refresh_token_rejects_garbage_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, _ = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                response = await client.post(
                    "/api/users/refresh-token",
                    json={"refresh_token": "not-a-jwt"},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401

    @pytest.mark.anyio
    async def test_refresh_token_rejects_disabled_user(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        database, app, user_service = await self._prepare(monkeypatch, tmp_path)
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                created = await self._create_user(database, user_service, "moluo", "password123")
                login_body = await self._login(client)
                async with database.async_session_maker() as session:
                    await user_service.disable_user(session, created["public_id"])
                response = await client.post(
                    "/api/users/refresh-token",
                    json={"refresh_token": login_body["refresh_token"]},
                )
        finally:
            await database.drop_db_and_tables()
            await database.engine.dispose()

        assert response.status_code == 401
