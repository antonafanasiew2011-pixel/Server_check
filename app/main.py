import asyncio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from app.database import Base, engine, AsyncSessionLocal
from starlette.middleware.authentication import AuthenticationMiddleware
from app.security import SessionAuthBackend
from app.routers import router
from app.monitor import monitor_loop, retention_job
from app.config import settings
from app.models import User, UserRole
from app.csrf import CSRFMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.security import hash_password


app = FastAPI(title=settings.app_name)
# Important: Session must wrap the app outermost so it's available to auth.
# In Starlette, the last added middleware runs first (outermost).
# app.add_middleware(CSRFMiddleware, secret_key=settings.secret_key)  # Temporarily disabled
app.add_middleware(AuthenticationMiddleware, backend=SessionAuthBackend())
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

templates = Jinja2Templates(directory="templates")
app.state.templates = templates

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(router)


@app.on_event("startup")
async def on_startup():
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # SQLite lightweight migration: ensure new columns exist
    async with engine.begin() as conn:
        # ensure users.active exists
        res = await conn.exec_driver_sql("PRAGMA table_info(users)")
        cols = [row[1] for row in res.fetchall()]
        if "active" not in cols:
            await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT 1")
        if "totp_enabled" not in cols:
            await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0")
        if "totp_secret" not in cols:
            await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)")
        # ensure audit_logs exists
        await conn.run_sync(Base.metadata.create_all)
        # ensure servers.tags exists
        res2 = await conn.exec_driver_sql("PRAGMA table_info(servers)")
        cols2 = [row[1] for row in res2.fetchall()]
        if "tags" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN tags VARCHAR(500)")
        # remote collection columns
        if "ssh_host" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN ssh_host VARCHAR(200)")
        if "ssh_port" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN ssh_port INTEGER DEFAULT 22")
        if "ssh_username" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN ssh_username VARCHAR(200)")
        if "ssh_password" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN ssh_password VARCHAR(200)")
        if "snmp_version" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN snmp_version VARCHAR(10)")
        if "snmp_community" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN snmp_community VARCHAR(200)")
        if "metric_source" not in cols2:
            await conn.exec_driver_sql("ALTER TABLE servers ADD COLUMN metric_source VARCHAR(20) DEFAULT 'auto'")

    # Ensure default admin exists for local login
    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(User).where(User.username == settings.admin_default_username))).scalar_one_or_none()
        if not existing:
            admin = User(
                username=settings.admin_default_username,
                full_name="Administrator",
                password_hash=hash_password(settings.admin_default_password),
                role=UserRole.admin.value,
                is_ldap=False,
            )
            db.add(admin)
            await db.commit()

    # Start background monitor
    asyncio.create_task(monitor_loop(AsyncSessionLocal))
    # Start retention job (daily)
    async def retention_scheduler():
        while True:
            await retention_job(AsyncSessionLocal)
            # run once per day
            await asyncio.sleep(24 * 60 * 60)
    asyncio.create_task(retention_scheduler())


@app.get("/health")
async def health():
    return {"status": "ok"}


