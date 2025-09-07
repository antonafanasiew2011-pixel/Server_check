from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.models import Server, Metric, AlertRule, AlertEvent
from datetime import datetime, timedelta


class MonitoringService:
    """Service layer for monitoring operations"""
    
    @staticmethod
    async def get_servers_with_latest_metrics(db: AsyncSession) -> List[Dict]:
        """Get all servers with their latest metrics in a single query"""
        # Use subquery to get latest metric for each server
        latest_metrics_subquery = (
            select(
                Metric.server_id,
                func.max(Metric.timestamp).label('latest_timestamp')
            )
            .group_by(Metric.server_id)
            .subquery()
        )
        
        # Join servers with their latest metrics
        query = (
            select(Server, Metric)
            .outerjoin(
                latest_metrics_subquery,
                Server.id == latest_metrics_subquery.c.server_id
            )
            .outerjoin(
                Metric,
                and_(
                    Metric.server_id == Server.id,
                    Metric.timestamp == latest_metrics_subquery.c.latest_timestamp
                )
            )
        )
        
        results = await db.execute(query)
        servers_data = []
        
        for server, metric in results:
            server_data = {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address,
                "system_name": server.system_name,
                "owner": server.owner,
                "is_cluster": server.is_cluster,
                "tags": server.tags,
                "metric_source": server.metric_source,
                "latest_metric": {
                    "timestamp": metric.timestamp.isoformat() if metric and metric.timestamp else None,
                    "cpu_percent": metric.cpu_percent if metric else None,
                    "cpu_temp": metric.cpu_temp if metric else None,
                    "ram_percent": metric.ram_percent if metric else None,
                    "swap_percent": metric.swap_percent if metric else None,
                    "disk_percent": metric.disk_percent if metric else None,
                    "disk_io_read": metric.disk_io_read if metric else None,
                    "disk_io_write": metric.disk_io_write if metric else None,
                    "processes": metric.processes if metric else None,
                    "network_in_kbps": metric.network_in_kbps if metric else None,
                    "network_out_kbps": metric.network_out_kbps if metric else None,
                    "network_io": round(((metric.network_in_kbps or 0) + (metric.network_out_kbps or 0)) / 1024, 2) if metric else None,  # Convert kbps to MB/s
                    "reachable": metric.reachable if metric else None,
                    "services_status": metric.services_status if metric else None,
                    "ports_status": metric.ports_status if metric else None,
                } if metric else None
            }
            servers_data.append(server_data)
        
        return servers_data
    
    @staticmethod
    async def get_server_metrics_history(
        db: AsyncSession, 
        server_id: int, 
        hours: int = 24
    ) -> List[Dict]:
        """Get metrics history for a server"""
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = (
            select(Metric)
            .where(
                and_(
                    Metric.server_id == server_id,
                    Metric.timestamp >= since
                )
            )
            .order_by(Metric.timestamp.asc())
        )
        
        results = await db.execute(query)
        metrics = results.scalars().all()
        
        return [
            {
                "timestamp": m.timestamp.isoformat(),
                "cpu_percent": m.cpu_percent,
                "cpu_temp": m.cpu_temp,
                "ram_percent": m.ram_percent,
                "swap_percent": m.swap_percent,
                "disk_percent": m.disk_percent,
                "disk_io_read": m.disk_io_read,
                "disk_io_write": m.disk_io_write,
                "processes": m.processes,
                "network_in_kbps": m.network_in_kbps,
                "network_out_kbps": m.network_out_kbps,
                "network_io": round(((m.network_in_kbps or 0) + (m.network_out_kbps or 0)) / 1024, 2),  # Convert kbps to MB/s
                "reachable": m.reachable,
                "services_status": m.services_status,
                "ports_status": m.ports_status,
            }
            for m in metrics
        ]
    
    @staticmethod
    async def evaluate_alerts_optimized(db: AsyncSession) -> None:
        """Optimized alert evaluation with batch queries"""
        # Get all enabled rules
        rules_query = select(AlertRule).where(AlertRule.enabled == True)
        rules = (await db.execute(rules_query)).scalars().all()
        
        if not rules:
            return
        
        # Get server IDs for batch query
        server_ids = [rule.server_id for rule in rules if rule.server_id]
        if not server_ids:
            return
        
        # Get latest metrics for all servers in one query
        latest_metrics_subquery = (
            select(
                Metric.server_id,
                func.max(Metric.timestamp).label('latest_timestamp')
            )
            .where(Metric.server_id.in_(server_ids))
            .group_by(Metric.server_id)
            .subquery()
        )
        
        latest_metrics_query = (
            select(Metric)
            .join(
                latest_metrics_subquery,
                and_(
                    Metric.server_id == latest_metrics_subquery.c.server_id,
                    Metric.timestamp == latest_metrics_subquery.c.latest_timestamp
                )
            )
        )
        
        latest_metrics = (await db.execute(latest_metrics_query)).scalars().all()
        metrics_by_server = {m.server_id: m for m in latest_metrics}
        
        # Evaluate each rule
        for rule in rules:
            if not rule.server_id:
                continue
                
            metric = metrics_by_server.get(rule.server_id)
            if not metric:
                continue
            
            # Map metric values
            metric_map = {
                "cpu": metric.cpu_percent,
                "cpu_temp": metric.cpu_temp,
                "ram": metric.ram_percent,
                "swap": metric.swap_percent,
                "disk": metric.disk_percent,
                "disk_io": (metric.disk_io_read or 0) + (metric.disk_io_write or 0),  # Combined disk I/O
                "processes": float(metric.processes) if metric.processes is not None else None,
                "net_in": metric.network_in_kbps,
                "net_out": metric.network_out_kbps,
                "network_io": round(((metric.network_in_kbps or 0) + (metric.network_out_kbps or 0)) / 1024, 2),  # Convert kbps to MB/s
                "reachable": 1.0 if metric.reachable else 0.0 if metric.reachable is not None else None,
            }
            
            val = metric_map.get(rule.metric)
            if _compare_metric(rule.operator, val, rule.threshold):
                message = f"Rule '{rule.name}' triggered on server {rule.server_id}: {rule.metric} {rule.operator} {rule.threshold} (value={val})"
                db.add(AlertEvent(rule_id=rule.id, server_id=rule.server_id, value=val, message=message))
                
                # Dispatch notifications
                try:
                    from app.monitor import dispatch_notifications
                    await dispatch_notifications(message)
                except Exception:
                    pass
        
        await db.commit()


def _compare_metric(op: str, value: float | None, threshold: float | None) -> bool:
    """Compare metric value with threshold"""
    if value is None or threshold is None:
        return False
    return {
        ">": value > threshold,
        "<": value < threshold,
        "=": value == threshold,
        "!=": value != threshold,
    }.get(op, False)
