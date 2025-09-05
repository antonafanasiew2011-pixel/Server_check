from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Form, Query
from fastapi.responses import RedirectResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from starlette.status import HTTP_302_FOUND
from app.database import get_db
from app.models import User, Server, Metric, UserRole, AuditLog
from app.models import AlertRule, AlertEvent, AlertGroup
from app.schemas import ServerCreate, ServerUpdate
from app.security import verify_password, hash_password
from app.ldap_utils import ldap_authenticate
from app.config import settings
from app.encryption import encrypt_password
from app.services import MonitoringService
from app.time_utils import format_moscow_time, format_moscow_time_short
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time


router = APIRouter()

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)

# In-memory rate limiting for login attempts
login_attempts = {}


def check_login_rate_limit(ip_address: str) -> bool:
    """Check if IP is rate limited for login attempts"""
    now = time.time()
    window = settings.login_rate_limit_window
    
    # Clean old entries
    login_attempts[ip_address] = [
        attempt_time for attempt_time in login_attempts.get(ip_address, [])
        if now - attempt_time < window
    ]
    
    # Check if limit exceeded
    attempts = login_attempts.get(ip_address, [])
    if len(attempts) >= settings.login_rate_limit_max_attempts:
        return False
    
    # Add current attempt
    login_attempts[ip_address] = attempts + [now]
    return True


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    servers = (await db.execute(select(Server))).scalars().all()
    return request.app.state.templates.TemplateResponse("dashboard.html", {"request": request, "servers": servers})


@router.get("/statistics")
async def statistics_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    return request.app.state.templates.TemplateResponse("statistics.html", {"request": request})


@router.get("/login")
async def login_page(request: Request):
    return request.app.state.templates.TemplateResponse("login.html", {"request": request, "ldap_enabled": settings.ldap_enabled})


@router.post("/login")
async def login(request: Request, db: AsyncSession = Depends(get_db), username: str = Form(...), password: str = Form(...), auth_type: str = Form("local"), use_ldap: bool = Form(False), totp: str = Form(None)):
    # Check rate limiting
    client_ip = get_remote_address(request)
    if not check_login_rate_limit(client_ip):
        db.add(AuditLog(username=username, action="login", details=f"rate limited from {client_ip}"))
        await db.commit()
        return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Слишком много попыток входа. Попробуйте позже.", "ldap_enabled": settings.ldap_enabled})
    
    # LDAP first if selected
    # Support legacy checkbox (use_ldap) and new radio (auth_type)
    wants_ldap = (auth_type == "ldap") or (use_ldap is True)
    if wants_ldap and settings.ldap_enabled:
        ldap_info = ldap_authenticate(username, password)
        if ldap_info:
            # Ensure user exists in DB
            existing = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
            if not existing:
                # Map groups to role
                role = UserRole.user.value
                groups = ldap_info.get("groups", []) if isinstance(ldap_info, dict) else []
                if settings.ldap_admin_group and any(settings.ldap_admin_group.lower() in g.lower() for g in groups):
                    role = UserRole.admin.value
                elif settings.ldap_user_group and any(settings.ldap_user_group.lower() in g.lower() for g in groups):
                    role = UserRole.user.value
                user = User(username=username, full_name=username, is_ldap=True, role=role)
                db.add(user)
                await db.commit()
            else:
                user = existing
            request.session["username"] = user.username
            request.session["role"] = user.role
            # audit login success (ldap)
            db.add(AuditLog(username=username, action="login", details="ldap success"))
            await db.commit()
            return RedirectResponse(url="/", status_code=HTTP_302_FOUND)

    # Local auth
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not user or not user.active or not user.password_hash or not verify_password(password, user.password_hash):
        # audit login failure
        db.add(AuditLog(username=username, action="login", details="local failed"))
        await db.commit()
        return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль", "ldap_enabled": settings.ldap_enabled})
    # If TOTP enabled, verify
    if user.totp_enabled:
        if not totp:
            return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Введите код 2FA", "ldap_enabled": settings.ldap_enabled})
        try:
            import pyotp
            if not (user.totp_secret and pyotp.TOTP(user.totp_secret).verify(totp)):
                return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Неверный 2FA код", "ldap_enabled": settings.ldap_enabled})
        except Exception:
            return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Ошибка проверки 2FA", "ldap_enabled": settings.ldap_enabled})
    request.session["username"] = user.username
    request.session["role"] = user.role
    db.add(AuditLog(username=username, action="login", details="local success"))
    await db.commit()
    return RedirectResponse(url="/", status_code=HTTP_302_FOUND)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)


@router.get("/servers")
async def list_servers(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str | None = None,
    cluster: str | None = None,  # 'yes' | 'no' | None
    reachable: str | None = None,  # 'yes' | 'no' | None
    environment: str | None = None,  # 'test' | 'stage' | 'prod' | None
    sort: str | None = None,  # hostname|ip|reachable|cpu|ram
    tag: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    servers = (await db.execute(select(Server))).scalars().all()

    # Attach latest metric snapshot per server
    enriched = []
    for s in servers:
        latest = (await db.execute(
            select(Metric).where(Metric.server_id == s.id).order_by(Metric.timestamp.desc()).limit(1)
        )).scalar_one_or_none()
        enriched.append((s, latest))

    # Filters
    if q:
        qlow = q.lower()
        enriched = [e for e in enriched if (qlow in e[0].hostname.lower()) or (qlow in e[0].ip_address.lower()) or (e[0].system_name and qlow in e[0].system_name.lower()) or (e[0].owner and qlow in e[0].owner.lower())]
    if cluster in {"yes", "no"}:
        want = cluster == "yes"
        enriched = [e for e in enriched if bool(e[0].is_cluster) == want]
    if reachable in {"yes", "no"}:
        want = reachable == "yes"
        enriched = [e for e in enriched if (e[1].reachable if e[1] is not None else False) == want]
    if environment in {"test", "stage", "prod"}:
        enriched = [e for e in enriched if e[0].environment == environment]
    if tag:
        t = tag.lower()
        enriched = [e for e in enriched if (e[0].tags and t in e[0].tags.lower())]

    # Sorting
    key_func = None
    reverse = False
    if sort == "hostname":
        key_func = lambda e: e[0].hostname.lower()
    elif sort == "ip":
        key_func = lambda e: e[0].ip_address
    elif sort == "reachable":
        key_func = lambda e: (e[1].reachable if e[1] is not None else False)
        reverse = True
    elif sort == "cpu":
        key_func = lambda e: (e[1].cpu_percent if (e[1] and e[1].cpu_percent is not None) else -1)
        reverse = True
    elif sort == "ram":
        key_func = lambda e: (e[1].ram_percent if (e[1] and e[1].ram_percent is not None) else -1)
        reverse = True
    if key_func:
        enriched.sort(key=key_func, reverse=reverse)

    # Pagination
    total_items = len(enriched)
    total_pages = (total_items + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_enriched = enriched[start_idx:end_idx]

    # Create pagination object
    class Pagination:
        def __init__(self, page, per_page, total, items):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = total_pages
            self.has_prev = page > 1
            self.has_next = page < total_pages
            self.prev_num = page - 1 if self.has_prev else None
            self.next_num = page + 1 if self.has_next else None
            
        def iter_pages(self, left_edge=2, right_edge=2, left_current=2, right_current=3):
            last = self.pages
            for num in range(1, last + 1):
                if num <= left_edge or \
                   (num > self.page - left_current - 1 and num < self.page + right_current) or \
                   num > last - right_edge:
                    yield num

    pagination = Pagination(page, per_page, total_items, paginated_enriched)

    is_admin = (request.session.get("role") == UserRole.admin.value) if hasattr(request, "session") else False
    return request.app.state.templates.TemplateResponse(
        "servers.html",
        {
            "request": request,
            "servers": [e[0] for e in paginated_enriched],
            "latest_map": {e[0].id: e[1] for e in paginated_enriched},
            "params": {"q": q or "", "cluster": cluster or "", "reachable": reachable or "", "environment": environment or "", "sort": sort or "", "tag": tag or ""},
            "is_admin": is_admin,
            "pagination": pagination,
        },
    )


@router.post("/servers")
async def create_server(request: Request, db: AsyncSession = Depends(get_db), hostname: str = Form(...), ip_address: str = Form(...), system_name: str = Form(""), owner: str = Form(""), is_cluster: bool = Form(False), environment: str = Form("prod"), tags: str = Form(""), ssh_host: str = Form(""), ssh_port: int = Form(22), ssh_username: str = Form(""), ssh_password: str = Form(""), snmp_version: str = Form(""), snmp_community: str = Form(""), services_to_monitor: str = Form(""), ports_to_monitor: str = Form("")):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Admins only")
    
    # Convert empty strings to None for optional fields
    def clean_string(value):
        return value.strip() if value and value.strip() else None
    
    system_name = clean_string(system_name)
    owner = clean_string(owner)
    tags = clean_string(tags)
    ssh_host = clean_string(ssh_host)
    ssh_username = clean_string(ssh_username)
    snmp_version = clean_string(snmp_version)
    
    # Encrypt sensitive data
    encrypted_ssh_password = encrypt_password(ssh_password) if ssh_password and ssh_password.strip() else None
    encrypted_snmp_community = encrypt_password(snmp_community) if snmp_community and snmp_community.strip() else None
    
    server = Server(hostname=hostname, ip_address=ip_address, system_name=system_name, owner=owner, is_cluster=is_cluster, environment=environment, tags=tags, ssh_host=ssh_host, ssh_port=ssh_port, ssh_username=ssh_username, ssh_password=encrypted_ssh_password, snmp_version=snmp_version, snmp_community=encrypted_snmp_community, services_to_monitor=clean_string(services_to_monitor), ports_to_monitor=clean_string(ports_to_monitor))
    db.add(server)
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="server_create", details=f"{hostname} {ip_address}"))
    await db.commit()
    return RedirectResponse(url="/servers", status_code=HTTP_302_FOUND)


@router.post("/servers/{server_id}/delete")
async def delete_server(request: Request, server_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Admins only")
    await db.execute(delete(Server).where(Server.id == server_id))
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="server_delete", details=str(server_id)))
    await db.commit()
    return RedirectResponse(url="/servers", status_code=HTTP_302_FOUND)


@router.get("/servers/{server_id}")
async def server_detail(request: Request, server_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return request.app.state.templates.TemplateResponse("server_detail.html", {"request": request, "server": server})


@router.get("/servers/{server_id}/edit")
async def edit_server_page(request: Request, server_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return request.app.state.templates.TemplateResponse("server_edit.html", {"request": request, "s": server})


@router.post("/servers/{server_id}/edit")
async def edit_server(request: Request, server_id: int, db: AsyncSession = Depends(get_db),
                      hostname: str = Form(...), ip_address: str = Form(...), system_name: str = Form(""),
                      owner: str = Form(""), is_cluster: bool = Form(False), environment: str = Form("prod"), tags: str = Form(""),
                      ssh_host: str = Form(""), ssh_port: int = Form(22), ssh_username: str = Form(""), ssh_password: str = Form(""),
                      snmp_version: str = Form(""), snmp_community: str = Form(""), services_to_monitor: str = Form(""), ports_to_monitor: str = Form(""), metric_source: str = Form("auto")):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Convert empty strings to None for optional fields
    def clean_string(value):
        return value.strip() if value and value.strip() else None
    
    server.hostname = hostname
    server.ip_address = ip_address
    server.system_name = clean_string(system_name)
    server.owner = clean_string(owner)
    server.is_cluster = is_cluster
    server.environment = environment
    server.tags = clean_string(tags)
    server.ssh_host = clean_string(ssh_host)
    server.ssh_port = ssh_port
    server.ssh_username = clean_string(ssh_username)
    server.services_to_monitor = clean_string(services_to_monitor)
    server.ports_to_monitor = clean_string(ports_to_monitor)
    # Only update password if provided (don't overwrite with empty)
    if ssh_password and ssh_password.strip():
        server.ssh_password = encrypt_password(ssh_password)
    server.snmp_version = clean_string(snmp_version)
    # Only update community if provided (don't overwrite with empty)
    if snmp_community and snmp_community.strip():
        server.snmp_community = encrypt_password(snmp_community)
    server.metric_source = metric_source
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="server_update", details=str(server_id)))
    await db.commit()
    return RedirectResponse(url=f"/servers/{server_id}", status_code=HTTP_302_FOUND)


# ---- API for metrics ----

@router.get("/api/servers")
async def api_servers(db: AsyncSession = Depends(get_db)):
    """Get all servers with latest metrics using optimized service"""
    servers_data = await MonitoringService.get_servers_with_latest_metrics(db)
    return JSONResponse(servers_data)


@router.get("/api/metrics/{server_id}")
async def api_metrics(server_id: int, db: AsyncSession = Depends(get_db), minutes: int = Query(120, ge=1, le=1440)):
    """Get metrics history for a server using optimized service"""
    hours = minutes // 60
    metrics_data = await MonitoringService.get_server_metrics_history(db, server_id, hours)
    return JSONResponse(metrics_data)


@router.get("/users")
async def users_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value}:
        raise HTTPException(status_code=403, detail="Admins only")
    users = (await db.execute(select(User))).scalars().all()
    return request.app.state.templates.TemplateResponse("users.html", {"request": request, "users": users, "roles": [UserRole.admin.value, UserRole.user.value]})


@router.get("/audit")
async def audit_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value}:
        raise HTTPException(status_code=403, detail="Admins only")
    logs = (await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200))).scalars().all()
    return request.app.state.templates.TemplateResponse("audit.html", {"request": request, "logs": logs, "format_moscow_time": format_moscow_time})


@router.post("/users")
async def create_user(request: Request, db: AsyncSession = Depends(get_db), username: str = Form(...), password: str = Form(...), full_name: str = Form(""), role: str = Form(UserRole.user.value)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Admins only")
    exists = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if exists:
        users = (await db.execute(select(User))).scalars().all()
        return request.app.state.templates.TemplateResponse("users.html", {"request": request, "users": users, "roles": [UserRole.admin.value, UserRole.user.value], "error": "Пользователь уже существует"})
    
    # Convert empty string to None for full_name
    parsed_full_name = full_name.strip() if full_name and full_name.strip() else None
    
    user = User(username=username, full_name=parsed_full_name, password_hash=hash_password(password), role=role, is_ldap=False)
    db.add(user)
    await db.commit()
    return RedirectResponse(url="/users", status_code=HTTP_302_FOUND)


# ---- Prometheus exporter ----

@router.get("/metrics")
async def prometheus_metrics(db: AsyncSession = Depends(get_db)):
    servers = (await db.execute(select(Server))).scalars().all()
    lines = []
    lines.append("# HELP server_reachable Server reachability by ping (1 reachable, 0 unreachable)")
    lines.append("# TYPE server_reachable gauge")
    lines.append("# HELP server_cpu_percent CPU usage percent for localhost targets")
    lines.append("# TYPE server_cpu_percent gauge")
    lines.append("# HELP server_ram_percent RAM usage percent for localhost targets")
    lines.append("# TYPE server_ram_percent gauge")
    lines.append("# HELP server_disk_percent Disk usage percent for localhost targets")
    lines.append("# TYPE server_disk_percent gauge")
    lines.append("# HELP server_processes Number of processes (localhost)")
    lines.append("# TYPE server_processes gauge")
    lines.append("# HELP server_net_in_kbps Network input kbps (localhost)")
    lines.append("# TYPE server_net_in_kbps gauge")
    lines.append("# HELP server_net_out_kbps Network output kbps (localhost)")
    lines.append("# TYPE server_net_out_kbps gauge")
    lines.append("# HELP server_cpu_temp CPU temperature in Celsius")
    lines.append("# TYPE server_cpu_temp gauge")
    lines.append("# HELP server_swap_percent Swap usage percent")
    lines.append("# TYPE server_swap_percent gauge")
    lines.append("# HELP server_disk_io_read Disk I/O read MB/s")
    lines.append("# TYPE server_disk_io_read gauge")
    lines.append("# HELP server_disk_io_write Disk I/O write MB/s")
    lines.append("# TYPE server_disk_io_write gauge")

    for s in servers:
        latest = (await db.execute(select(Metric).where(Metric.server_id == s.id).order_by(Metric.timestamp.desc()).limit(1))).scalar_one_or_none()
        def esc(v: str) -> str:
            return v.replace('\\', '\\\\').replace('"', '\\"')
        labels = f'server_id="{s.id}",hostname="{esc(s.hostname)}",ip="{esc(s.ip_address)}"'
        if latest is None:
            continue
        if latest.reachable is not None:
            lines.append(f"server_reachable{{{labels}}} {1 if latest.reachable else 0}")
        if latest.cpu_percent is not None:
            lines.append(f"server_cpu_percent{{{labels}}} {latest.cpu_percent}")
        if latest.ram_percent is not None:
            lines.append(f"server_ram_percent{{{labels}}} {latest.ram_percent}")
        if latest.disk_percent is not None:
            lines.append(f"server_disk_percent{{{labels}}} {latest.disk_percent}")
        if latest.processes is not None:
            lines.append(f"server_processes{{{labels}}} {latest.processes}")
        if latest.network_in_kbps is not None:
            lines.append(f"server_net_in_kbps{{{labels}}} {latest.network_in_kbps}")
        if latest.network_out_kbps is not None:
            lines.append(f"server_net_out_kbps{{{labels}}} {latest.network_out_kbps}")
        if latest.cpu_temp is not None:
            lines.append(f"server_cpu_temp{{{labels}}} {latest.cpu_temp}")
        if latest.swap_percent is not None:
            lines.append(f"server_swap_percent{{{labels}}} {latest.swap_percent}")
        if latest.disk_io_read is not None:
            lines.append(f"server_disk_io_read{{{labels}}} {latest.disk_io_read}")
        if latest.disk_io_write is not None:
            lines.append(f"server_disk_io_write{{{labels}}} {latest.disk_io_write}")

    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4")


@router.get("/profile")
async def profile_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    username = request.session.get("username")
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user})


@router.post("/profile/password")
async def profile_password(request: Request, db: AsyncSession = Depends(get_db), current_password: str = Form(...), new_password: str = Form(...)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    username = request.session.get("username")
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_ldap:
        return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user, "error": "Смена пароля недоступна для LDAP"})
    if not verify_password(current_password, user.password_hash or ""):
        return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user, "error": "Текущий пароль неверный"})
    user.password_hash = hash_password(new_password)
    await db.commit()
    return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user, "success": "Пароль обновлён"})


@router.post("/profile/2fa")
async def profile_2fa(request: Request, db: AsyncSession = Depends(get_db), action: str = Form(...)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    username = request.session.get("username")
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_ldap:
        return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user, "error": "2FA недоступна для LDAP"})
    import secrets
    import pyotp
    if action == "enable":
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()
        user.totp_enabled = True
    elif action == "disable":
        user.totp_enabled = False
    await db.commit()
    return request.app.state.templates.TemplateResponse("profile.html", {"request": request, "user": user, "success": "Настройки 2FA обновлены"})


@router.post("/users/{user_id}/role")
async def change_user_role(request: Request, user_id: int, role: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Admins only")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = role
    await db.commit()
    return RedirectResponse(url="/users", status_code=HTTP_302_FOUND)


# ---- Alerts UI ----

@router.get("/alerts")
async def alerts_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    rules = (await db.execute(select(AlertRule))).scalars().all()
    events = (await db.execute(select(AlertEvent).order_by(AlertEvent.timestamp.desc()).limit(50))).scalars().all()
    servers = (await db.execute(select(Server))).scalars().all()
    groups = (await db.execute(select(AlertGroup))).scalars().all()
    return request.app.state.templates.TemplateResponse("alerts.html", {"request": request, "rules": rules, "events": events, "servers": servers, "groups": groups, "format_moscow_time": format_moscow_time})


@router.post("/alerts")
async def create_alert_rule(request: Request, db: AsyncSession = Depends(get_db), name: str = Form(...), server_id: int = Form(...), group_id: str = Form(""), metric: str = Form(...), operator: str = Form(...), threshold: float = Form(None), severity: str = Form("warning")):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    
    # Parse group_id - convert empty string to None
    parsed_group_id = None
    if group_id and group_id.strip():
        try:
            parsed_group_id = int(group_id)
        except ValueError:
            parsed_group_id = None
    
    rule = AlertRule(name=name, server_id=server_id, group_id=parsed_group_id, metric=metric, operator=operator, threshold=threshold, severity=severity, enabled=True)
    db.add(rule)
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="alert_create", details=name))
    await db.commit()
    return RedirectResponse(url="/alerts", status_code=HTTP_302_FOUND)


# ---- CSV import/export ----

@router.get("/servers/export.csv")
async def export_servers_csv(db: AsyncSession = Depends(get_db)):
    servers = (await db.execute(select(Server))).scalars().all()
    def gen():
        yield "hostname,ip_address,system_name,owner,is_cluster,tags\n".encode("utf-8")
        for s in servers:
            row = [
                s.hostname or "",
                s.ip_address or "",
                (s.system_name or "").replace(",", " "),
                (s.owner or "").replace(",", " "),
                "true" if s.is_cluster else "false",
                (s.tags or "").replace(",", ";"),
            ]
            yield (",").join(row).encode("utf-8") + b"\n"
    return StreamingResponse(gen(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=servers.csv"})


@router.post("/servers/import.csv")
async def import_servers_csv(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Admins/Operators only")
    form = await request.form()
    file = form.get("file")
    if not file:
        raise HTTPException(status_code=400, detail="CSV file is required")
    import io, csv
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        hostname = (row.get('hostname') or '').strip()
        ip = (row.get('ip_address') or '').strip()
        if not hostname or not ip:
            continue
        system_name = (row.get('system_name') or '').strip() or None
        owner = (row.get('owner') or '').strip() or None
        is_cluster = (row.get('is_cluster') or '').strip().lower() in {"1","true","yes"}
        tags = (row.get('tags') or '').strip() or None
        server = Server(hostname=hostname, ip_address=ip, system_name=system_name, owner=owner, is_cluster=is_cluster, tags=tags)
        db.add(server)
    await db.commit()
    return RedirectResponse(url="/servers", status_code=HTTP_302_FOUND)


@router.post("/alerts/{rule_id}/toggle")
async def toggle_alert_rule(request: Request, rule_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    rule = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="alert_toggle", details=str(rule_id)))
    await db.commit()
    return RedirectResponse(url="/alerts", status_code=HTTP_302_FOUND)


@router.post("/alerts/{rule_id}/delete")
async def delete_alert_rule(request: Request, rule_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    await db.execute(delete(AlertRule).where(AlertRule.id == rule_id))
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="alert_delete", details=str(rule_id)))
    await db.commit()
    return RedirectResponse(url="/alerts", status_code=HTTP_302_FOUND)


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(request: Request, user_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Admins only")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.active = False
    await db.commit()
    return RedirectResponse(url="/users", status_code=HTTP_302_FOUND)


@router.post("/users/{user_id}/activate")
async def activate_user(request: Request, user_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Admins only")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.active = True
    await db.commit()
    return RedirectResponse(url="/users", status_code=HTTP_302_FOUND)


@router.post("/users/{user_id}/password")
async def set_user_password(request: Request, user_id: int, new_password: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Admins only")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_ldap:
        raise HTTPException(status_code=400, detail="Cannot change password for LDAP users")
    user.password_hash = hash_password(new_password)
    await db.commit()
    return RedirectResponse(url="/users", status_code=HTTP_302_FOUND)


# ---- Alert Groups Management ----

@router.get("/alert-groups")
async def alert_groups_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    groups = (await db.execute(select(AlertGroup))).scalars().all()
    return request.app.state.templates.TemplateResponse("alert_groups.html", {"request": request, "groups": groups})


@router.post("/alert-groups")
async def create_alert_group(request: Request, db: AsyncSession = Depends(get_db), name: str = Form(...), description: str = Form("")):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    
    # Convert empty string to None for description
    parsed_description = description.strip() if description and description.strip() else None
    
    group = AlertGroup(name=name, description=parsed_description, enabled=True)
    db.add(group)
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="alert_group_create", details=name))
    await db.commit()
    return RedirectResponse(url="/alert-groups", status_code=HTTP_302_FOUND)


@router.post("/alert-groups/{group_id}/delete")
async def delete_alert_group(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    if request.session.get("role") not in {UserRole.admin.value, UserRole.operator.value}:
        raise HTTPException(status_code=403, detail="Operators/Admins only")
    await db.execute(delete(AlertGroup).where(AlertGroup.id == group_id))
    await db.commit()
    db.add(AuditLog(username=request.session.get("username"), action="alert_group_delete", details=str(group_id)))
    await db.commit()
    return RedirectResponse(url="/alert-groups", status_code=HTTP_302_FOUND)


# ---- PDF Export ----

@router.get("/reports/export.pdf")
async def export_report_pdf(request: Request, db: AsyncSession = Depends(get_db), 
                          report_type: str = Query("servers", regex="^(servers|alerts|metrics)$"),
                          server_id: int = Query(None)):
    if not request.user.is_authenticated:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        import io
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("Server Check Report", title_style))
        story.append(Spacer(1, 12))
        
        if report_type == "servers":
            # Servers report
            servers = (await db.execute(select(Server))).scalars().all()
            
            # Create table data
            data = [['Hostname', 'IP Address', 'System', 'Owner', 'Environment', 'Status']]
            
            for server in servers:
                # Get latest metric
                latest_metric = (await db.execute(
                    select(Metric).where(Metric.server_id == server.id)
                    .order_by(Metric.timestamp.desc()).limit(1)
                )).scalar_one_or_none()
                
                status = "Unknown"
                if latest_metric:
                    status = "Online" if latest_metric.reachable else "Offline"
                
                data.append([
                    server.hostname,
                    server.ip_address,
                    server.system_name or "—",
                    server.owner or "—",
                    server.environment,
                    status
                ])
            
            # Create table
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            
        elif report_type == "alerts":
            # Alerts report
            rules = (await db.execute(select(AlertRule))).scalars().all()
            events = (await db.execute(select(AlertEvent).order_by(AlertEvent.timestamp.desc()).limit(50))).scalars().all()
            
            # Rules table
            story.append(Paragraph("Alert Rules", styles['Heading2']))
            data = [['Name', 'Metric', 'Condition', 'Status']]
            for rule in rules:
                data.append([
                    rule.name,
                    rule.metric,
                    f"{rule.operator} {rule.threshold}",
                    "Enabled" if rule.enabled else "Disabled"
                ])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Recent events
            story.append(Paragraph("Recent Alert Events", styles['Heading2']))
            data = [['Time', 'Rule ID', 'Server ID', 'Value', 'Message']]
            for event in events:
                data.append([
                    event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    str(event.rule_id),
                    str(event.server_id),
                    str(event.value) if event.value else "—",
                    event.message[:50] + "..." if len(event.message) > 50 else event.message
                ])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return Response(
            content=buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=server_check_report_{report_type}.pdf"}
        )
        
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab package. Install with: pip install reportlab")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

