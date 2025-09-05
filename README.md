# Server Check

FastAPI web app to manage servers (hostname, IP, system, owner, cluster flag), monitor reachability and local metrics, with local and LDAP login.

## 🔒 Security Features

- **Rate Limiting**: Login attempts limited to 5 per 5 minutes per IP
- **CSRF Protection**: Temporarily disabled for development (can be re-enabled)
- **Password Encryption**: SSH/SNMP passwords encrypted with Fernet
- **TOTP 2FA**: Two-factor authentication for local users
- **Audit Logging**: All user actions logged for security

## 🚀 Performance Optimizations

- **Database Indexes**: Optimized queries with proper indexing
- **Service Layer**: Clean separation of business logic
- **Batch Queries**: Reduced N+1 problems in monitoring
- **Connection Pooling**: Efficient database connections

## 🎨 UI/UX Improvements

- **Dark Theme**: Toggle between light and dark modes
- **Loading Indicators**: Visual feedback for all operations
- **Real-time Updates**: Auto-refresh dashboard every 30 seconds
- **Form Validation**: Client-side validation with error messages
- **Responsive Design**: Works on desktop and mobile devices

Setup (PowerShell)

1) Create venv and install deps:

python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt

2) Run server:

.\.venv\Scripts\uvicorn app.main:app --reload --port 8000

Open http://localhost:8000

Default admin: admin / admin123

Optional LDAP env in .env or system env:

LDAP_ENABLED=true
LDAP_SERVER=ldap.company.local
LDAP_PORT=389
LDAP_USE_SSL=false
LDAP_BIND_DN=cn=ldapreader,ou=service,dc=company,dc=local
LDAP_BIND_PASSWORD=secret
LDAP_USER_BASE_DN=ou=users,dc=company,dc=local
LDAP_USER_FILTER=(sAMAccountName={username})

Remote metrics (SSH/SNMP)

SSH (Linux):
- Fill fields on server create/edit: ssh_host, ssh_port (22), ssh_username, ssh_password
- Metrics collected: CPU, RAM, Disk, Processes (basic commands: top/free/df/ps)
- For key auth, use an SSH agent or set up password field for now

SNMP v2c:
- Enable SNMP and Host Resources MIB on the target
- Open UDP 161 between app and target
- Fill snmp_version=v2c and snmp_community
- Metrics: hrProcessorLoad (CPU avg), hrSystemProcesses, hrStorageTable (RAM/Disk %)
- Timeouts are short (~1.5s, no retries) to avoid long waits

Metric source selection:
- Each server has metric_source: auto | local | ssh | snmp
- auto: localhost -> local; otherwise prefer SSH if set, else SNMP if set, else ping only
- Change on /servers/{id}/edit

Prometheus/Grafana

- Prometheus scrape endpoint: /metrics
- Example panels/graphs in grafana/dashboard.json (import in Grafana UI)

Notifications

Configure any of the following to receive alerts:
- SMTP: SMTP_HOST/PORT/USE_TLS/USERNAME/PASSWORD/SMTP_FROM
- Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
- Webhook: DEFAULT_WEBHOOK_URL

Two‑factor (TOTP)

- Local users can enable 2FA in /profile; login form accepts a TOTP code if enabled

Alembic migrations

- Initialize (already included): alembic.ini, alembic/
- Create revision (after model changes):
  .\.venv\Scripts\alembic revision --autogenerate -m "message"
- Apply migrations:
  .\.venv\Scripts\alembic upgrade head

Dependencies

New packages used:
- httpx (Telegram/Webhook)
- asyncssh (SSH metrics)
- pysnmp (SNMP v2c)
- pyotp (2FA)

