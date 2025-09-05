from pydantic_settings import BaseSettings
from typing import Optional
import secrets

class Settings(BaseSettings):
    # Application
    app_name: str = "Server Check"
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./server_check.db"
    
    # Security
    secret_key: str = secrets.token_urlsafe(32)
    encryption_key: str = secrets.token_urlsafe(32)
    
    # Default admin user
    admin_default_username: str = "admin"
    admin_default_password: str = "admin123"
    
    # LDAP
    ldap_enabled: bool = False
    ldap_server: Optional[str] = None
    ldap_port: int = 389
    ldap_base_dn: Optional[str] = None
    ldap_bind_dn: Optional[str] = None
    ldap_bind_password: Optional[str] = None
    ldap_user_search_base: Optional[str] = None
    ldap_user_filter: str = "(uid={username})"
    ldap_group_search_base: Optional[str] = None
    ldap_group_filter: str = "(member={user_dn})"
    ldap_admin_group: str = "admins"
    ldap_operator_group: str = "operators"
    
    # Monitoring
    monitoring_interval: int = 60  # seconds
    monitor_interval_seconds: int = 60  # seconds (alias for compatibility)
    metrics_retention_days: int = 30
    retention_days: int = 30  # alias for compatibility
    alert_evaluation_interval: int = 300  # seconds
    max_concurrency: int = 10  # maximum concurrent monitoring tasks
    
    # Rate limiting
    login_rate_limit_window: int = 900  # 15 minutes
    login_rate_limit_max_attempts: int = 5
    
    # Notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_use_tls: bool = True
    
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    
    webhook_url: Optional[str] = None
    
    # Remote monitoring
    ssh_timeout: int = 10
    snmp_timeout: int = 5
    snmp_retries: int = 3
    ping_timeout_seconds: int = 3
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Create settings instance
settings = Settings()