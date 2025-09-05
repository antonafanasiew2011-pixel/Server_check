"""Add security improvements and indexes

Revision ID: 0002_security_improvements
Revises: 0001_add_indexes
Create Date: 2024-01-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0002_security_improvements'
down_revision = '0001_add_indexes'
branch_labels = None
depends_on = None


def upgrade():
    # Add indexes for performance
    op.create_index('idx_metrics_server_timestamp', 'metrics', ['server_id', 'timestamp'])
    op.create_index('idx_alert_events_rule_timestamp', 'alert_events', ['rule_id', 'timestamp'])
    op.create_index('idx_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    
    # Extend column sizes for encrypted data
    op.alter_column('servers', 'ssh_password', type_=sa.String(500))
    op.alter_column('servers', 'snmp_community', type_=sa.String(500))


def downgrade():
    # Remove indexes
    op.drop_index('idx_metrics_server_timestamp', 'metrics')
    op.drop_index('idx_alert_events_rule_timestamp', 'alert_events')
    op.drop_index('idx_audit_logs_timestamp', 'audit_logs')
    
    # Revert column sizes
    op.alter_column('servers', 'ssh_password', type_=sa.String(200))
    op.alter_column('servers', 'snmp_community', type_=sa.String(200))
