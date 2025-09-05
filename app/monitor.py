import asyncio
import time
from datetime import datetime
from typing import Dict, Tuple
import psutil
from pythonping import ping
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import Server, Metric, AlertRule, AlertEvent
from app.config import settings
from app.encryption import decrypt_password
from app.services import MonitoringService
import smtplib
from email.message import EmailMessage
import httpx


async def collect_local_metrics() -> Tuple[float, float, float, float, float, float, int, float, float, float, float]:
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory().percent
    swap = psutil.swap_memory().percent
    disk = psutil.disk_usage('/').percent
    processes = len(psutil.pids())
    
    # Network I/O
    net_io_1 = psutil.net_io_counters()
    await asyncio.sleep(1)
    net_io_2 = psutil.net_io_counters()
    in_kbps = (net_io_2.bytes_recv - net_io_1.bytes_recv) * 8 / 1024
    out_kbps = (net_io_2.bytes_sent - net_io_1.bytes_sent) * 8 / 1024
    
    # Disk I/O
    disk_io_1 = psutil.disk_io_counters()
    await asyncio.sleep(1)
    disk_io_2 = psutil.disk_io_counters()
    disk_read_mb = (disk_io_2.read_bytes - disk_io_1.read_bytes) / (1024 * 1024)
    disk_write_mb = (disk_io_2.write_bytes - disk_io_1.write_bytes) / (1024 * 1024)
    
    # CPU Temperature (Linux only)
    cpu_temp = None
    try:
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    if 'core' in name.lower() or 'cpu' in name.lower():
                        for entry in entries:
                            if entry.current is not None:
                                cpu_temp = entry.current
                                break
                        if cpu_temp is not None:
                            break
    except Exception:
        pass
    
    return cpu, cpu_temp, ram, swap, disk, disk_read_mb, disk_write_mb, processes, in_kbps, out_kbps


async def _probe_server(server: Server):
    reachable = False
    cpu = cpu_temp = ram = swap = disk = disk_read = disk_write = in_kbps = out_kbps = None
    processes = None
    services_status = None
    ports_status = None
    
    try:
        resp = ping(server.ip_address, count=1, timeout=settings.ping_timeout_seconds)
        reachable = resp.success()
    except Exception:
        reachable = False

    # Decide source preference
    source = (server.metric_source or "auto")
    is_local = server.ip_address in {"127.0.0.1", "::1", "localhost"} or server.hostname in {"localhost"}

    # Local metrics if localhost (or forced local)
    if (source == "local" and is_local) or (source == "auto" and is_local):
        try:
            cpu, cpu_temp, ram, swap, disk, disk_read, disk_write, processes, in_kbps, out_kbps = await collect_local_metrics()
            
            # Check services status
            if server.services_to_monitor:
                try:
                    import json
                    services_list = json.loads(server.services_to_monitor)
                    services_status = {}
                    for service in services_list:
                        try:
                            # Check if service is running (Linux)
                            import subprocess
                            result = subprocess.run(['systemctl', 'is-active', service], 
                                                  capture_output=True, text=True, timeout=5)
                            services_status[service] = result.stdout.strip() == 'active'
                        except Exception:
                            services_status[service] = False
                    services_status = json.dumps(services_status)
                except Exception:
                    pass
            
            # Check ports status
            if server.ports_to_monitor:
                try:
                    import json
                    import socket
                    ports_list = json.loads(server.ports_to_monitor)
                    ports_status = {}
                    for port in ports_list:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex(('127.0.0.1', int(port)))
                            ports_status[str(port)] = result == 0
                            sock.close()
                        except Exception:
                            ports_status[str(port)] = False
                    ports_status = json.dumps(ports_status)
                except Exception:
                    pass
                    
        except Exception:
            pass
    # SSH metrics (forced or auto when ssh configured)
    elif (source == "ssh") or (source == "auto" and server.ssh_host and server.ssh_username):
        try:
            import asyncssh  # lightweight alternative to paramiko in async
            ssh_password = decrypt_password(server.ssh_password) if server.ssh_password else None
            async with asyncssh.connect(server.ssh_host, port=server.ssh_port or 22, username=server.ssh_username, password=ssh_password, known_hosts=None) as conn:
                cpu_out = await conn.run("LANG=C top -bn1 | grep 'Cpu' | awk '{print 100-$8}'", check=False)
                ram_out = await conn.run("free -m | awk 'NR==2{printf \"%.2f\", $3*100/$2 }'", check=False)
                disk_out = await conn.run("df -h / | awk 'NR==2{gsub(/%/,\"\",$5); print $5}'", check=False)
                ps_out = await conn.run("ps -e --no-headers | wc -l", check=False)
                try:
                    cpu = float(cpu_out.stdout.strip()) if cpu_out.stdout else None
                except Exception:
                    cpu = None
                try:
                    ram = float(ram_out.stdout.strip()) if ram_out.stdout else None
                except Exception:
                    ram = None
                try:
                    disk = float(disk_out.stdout.strip()) if disk_out.stdout else None
                except Exception:
                    disk = None
                try:
                    processes = int(ps_out.stdout.strip()) if ps_out.stdout else None
                except Exception:
                    processes = None
        except Exception:
            pass
    # SNMP metrics (forced or auto when snmp configured)
    elif (source == "snmp") or (source == "auto" and server.snmp_version == "v2c" and server.snmp_community and server.ip_address):
        try:
            from pysnmp.hlapi.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget,
                                              ContextData, ObjectType, ObjectIdentity, getCmd, bulkCmd)

            engine = SnmpEngine()
            target = UdpTransportTarget((server.ip_address, 161), timeout=1.5, retries=0)
            snmp_community = decrypt_password(server.snmp_community) if server.snmp_community else "public"
            community = CommunityData(snmp_community, mpModel=1)
            ctx = ContextData()

            # Processes: hrSystemProcesses.0
            errInd, errStat, errIdx, varBinds = await getCmd(
                engine, community, target, ctx,
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.1.6.0'))
            )
            if (not errInd) and (not errStat):
                try:
                    processes = int(varBinds[0][1])
                except Exception:
                    processes = processes

            # CPU: hrProcessorLoad 1.3.6.1.2.1.25.3.3.1.2 - average across instances
            cpu_values = []
            async for (errInd2, errStat2, errIdx2, varBinds2) in bulkCmd(
                engine, community, target, ctx, 0, 10,
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.3.1.2')),
                lexicographicMode=False
            ):
                if errInd2 or errStat2:
                    break
                for name, val in varBinds2:
                    oid = str(name)
                    if not oid.startswith('1.3.6.1.2.1.25.3.3.1.2'):
                        continue
                    try:
                        cpu_values.append(float(val))
                    except Exception:
                        pass
            if cpu_values:
                cpu = sum(cpu_values) / len(cpu_values)

            # Storage: hrStorageTable 1.3.6.1.2.1.25.2.3
            # Types: hrStorageType 1.3.6.1.2.1.25.2.3.1.2
            # AllocationUnits: 1.3.6.1.2.1.25.2.3.1.4, Size: ...1.5, Used: ...1.6
            hrStorageType = '1.3.6.1.2.1.25.2.3.1.2'
            hrAllocUnits = '1.3.6.1.2.1.25.2.3.1.4'
            hrSize = '1.3.6.1.2.1.25.2.3.1.5'
            hrUsed = '1.3.6.1.2.1.25.2.3.1.6'
            # type OIDs
            hrStorageRam = '1.3.6.1.2.1.25.2.1.2'
            hrStorageFixedDisk = '1.3.6.1.2.1.25.2.1.4'

            storage = {}
            async for (e3, s3, i3, binds3) in bulkCmd(engine, community, target, ctx, 0, 25,
                                                      ObjectType(ObjectIdentity(hrStorageType)),
                                                      ObjectType(ObjectIdentity(hrAllocUnits)),
                                                      ObjectType(ObjectIdentity(hrSize)),
                                                      ObjectType(ObjectIdentity(hrUsed)),
                                                      lexicographicMode=False):
                if e3 or s3:
                    break
                # binds3 is a list of varBinds for multiple columns
                # normalize rows by index suffix
                for name, val in binds3:
                    oid = str(name)
                    if oid.startswith(hrStorageType):
                        idx = oid[len(hrStorageType)+1:]
                        storage.setdefault(idx, {})['type'] = str(val)
                    elif oid.startswith(hrAllocUnits):
                        idx = oid[len(hrAllocUnits)+1:]
                        storage.setdefault(idx, {})['au'] = int(val)
                    elif oid.startswith(hrSize):
                        idx = oid[len(hrSize)+1:]
                        storage.setdefault(idx, {})['size'] = int(val)
                    elif oid.startswith(hrUsed):
                        idx = oid[len(hrUsed)+1:]
                        storage.setdefault(idx, {})['used'] = int(val)
            # compute RAM and Disk percents
            ram_percent = None
            disk_percent = None
            # RAM: pick the hrStorageRam row
            for idx, row in storage.items():
                if row.get('type') and row['type'].endswith(hrStorageRam):
                    try:
                        total = row['size'] * row['au']
                        used = row['used'] * row['au']
                        if total > 0:
                            ram_percent = (used / total) * 100.0
                    except Exception:
                        pass
                    break
            # Disk: aggregate fixed disks
            total_disk = 0
            used_disk = 0
            for idx, row in storage.items():
                if row.get('type') and row['type'].endswith(hrStorageFixedDisk):
                    try:
                        total_disk += row['size'] * row['au']
                        used_disk += row['used'] * row['au']
                    except Exception:
                        pass
            if total_disk > 0:
                disk_percent = (used_disk / total_disk) * 100.0

            if ram_percent is not None:
                ram = ram_percent
            if disk_percent is not None:
                disk = disk_percent
        except Exception:
            pass

    return {
        "server_id": server.id,
        "cpu": cpu,
        "cpu_temp": cpu_temp,
        "ram": ram,
        "swap": swap,
        "disk": disk,
        "disk_read": disk_read,
        "disk_write": disk_write,
        "processes": processes,
        "in_kbps": in_kbps,
        "out_kbps": out_kbps,
        "reachable": reachable,
        "services_status": services_status,
        "ports_status": ports_status,
    }


async def monitor_once(db: AsyncSession):
    servers = (await db.execute(select(Server))).scalars().all()
    sem = asyncio.Semaphore(settings.max_concurrency)

    async def wrapped(s: Server):
        async with sem:
            return await _probe_server(s)

    results = await asyncio.gather(*(wrapped(s) for s in servers), return_exceptions=False)
    for r in results:
        metric = Metric(
            server_id=r["server_id"],
            cpu_percent=r["cpu"],
            cpu_temp=r["cpu_temp"],
            ram_percent=r["ram"],
            swap_percent=r["swap"],
            disk_percent=r["disk"],
            disk_io_read=r["disk_read"],
            disk_io_write=r["disk_write"],
            processes=r["processes"],
            network_in_kbps=r["in_kbps"],
            network_out_kbps=r["out_kbps"],
            reachable=r["reachable"],
            services_status=r["services_status"],
            ports_status=r["ports_status"],
        )
        db.add(metric)
    await db.commit()


def _compare(op: str, value: float | None, threshold: float | None) -> bool:
    if value is None or threshold is None:
        return False
    return {
        ">": value > threshold,
        "<": value < threshold,
        "=": value == threshold,
        "!=": value != threshold,
    }.get(op, False)


async def evaluate_alerts(db: AsyncSession):
    """Use optimized alert evaluation service"""
    await MonitoringService.evaluate_alerts_optimized(db)


async def monitor_loop(db_factory, interval_seconds: int | None = None):
    if interval_seconds is None:
        interval_seconds = settings.monitor_interval_seconds
    while True:
        async with db_factory() as db:
            await monitor_once(db)
            await evaluate_alerts(db)
        await asyncio.sleep(interval_seconds)


async def retention_job(db_factory):
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(days=settings.retention_days)
    from sqlalchemy import delete as sqldelete
    async with db_factory() as db:
        await db.execute(sqldelete(Metric).where(Metric.timestamp < cutoff))
        await db.commit()


async def dispatch_notifications(message: str):
    # Email
    smtp_from = settings.smtp_from or settings.smtp_from_email
    if settings.smtp_host and smtp_from:
        try:
            msg = EmailMessage()
            msg["Subject"] = "Server Check Alert"
            msg["From"] = smtp_from
            msg["To"] = smtp_from
            msg.set_content(message)
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
                if settings.smtp_use_tls:
                    s.starttls()
                if settings.smtp_username and settings.smtp_password:
                    s.login(settings.smtp_username, settings.smtp_password)
                s.send_message(msg)
        except Exception:
            pass
    
    # Telegram
    if settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(url, json={"chat_id": settings.telegram_chat_id, "text": message})
        except Exception:
            pass
    
    # Slack
    if settings.slack_webhook_url:
        try:
            payload = {
                "text": f"🚨 Server Check Alert",
                "attachments": [
                    {
                        "color": "danger",
                        "text": message,
                        "footer": "Server Check",
                        "ts": int(time.time())
                    }
                ]
            }
            if settings.slack_channel:
                payload["channel"] = settings.slack_channel
            
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(settings.slack_webhook_url, json=payload)
        except Exception:
            pass
    
    # Discord
    if settings.discord_webhook_url:
        try:
            payload = {
                "content": f"🚨 **Server Check Alert**",
                "embeds": [
                    {
                        "title": "Alert Notification",
                        "description": message,
                        "color": 15158332,  # Red color
                        "timestamp": datetime.utcnow().isoformat(),
                        "footer": {"text": "Server Check"}
                    }
                ]
            }
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(settings.discord_webhook_url, json=payload)
        except Exception:
            pass
    
    # Webhook
    webhook_url = settings.default_webhook_url or settings.webhook_url
    if webhook_url:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(webhook_url, json={"message": message})
        except Exception:
            pass


