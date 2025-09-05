import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"
    operator = "operator"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(200), nullable=True)
    password_hash = Column(String(255), nullable=True)
    is_ldap = Column(Boolean, default=False)
    role = Column(String(20), default=UserRole.user.value)
    active = Column(Boolean, default=True)
    totp_enabled = Column(Boolean, default=False)
    totp_secret = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(200), nullable=False)
    ip_address = Column(String(100), nullable=False)
    system_name = Column(String(200), nullable=True)
    owner = Column(String(200), nullable=True)
    is_cluster = Column(Boolean, default=False)
    tags = Column(String(500), nullable=True)
    # Remote collection settings
    ssh_host = Column(String(200), nullable=True)
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String(200), nullable=True)
    ssh_password = Column(String(500), nullable=True)  # Encrypted
    snmp_version = Column(String(10), nullable=True)  # v2c
    snmp_community = Column(String(500), nullable=True)  # Encrypted
    metric_source = Column(String(20), default="auto")  # auto|local|ssh|snmp
    created_at = Column(DateTime, default=datetime.utcnow)

    metrics = relationship("Metric", back_populates="server", cascade="all, delete-orphan")


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_percent = Column(Float, nullable=True)
    ram_percent = Column(Float, nullable=True)
    disk_percent = Column(Float, nullable=True)
    processes = Column(Integer, nullable=True)
    network_in_kbps = Column(Float, nullable=True)
    network_out_kbps = Column(Float, nullable=True)
    reachable = Column(Boolean, default=None)

    server = relationship("Server", back_populates="metrics")


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=True)
    metric = Column(String(50), nullable=False)  # cpu|ram|disk|reachable|processes|net_in|net_out
    operator = Column(String(5), nullable=False)  # >, <, =, !=
    threshold = Column(Float, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    server = relationship("Server", backref="alert_rules")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    value = Column(Float, nullable=True)
    message = Column(String(500), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(String(1000), nullable=True)


