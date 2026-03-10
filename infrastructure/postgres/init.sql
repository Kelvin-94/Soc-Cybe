CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS soc_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(160) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_role_permissions (
    role_id UUID NOT NULL REFERENCES soc_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES soc_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS soc_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    role_id UUID REFERENCES soc_roles(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    consent_logged BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS soc_consent_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID NOT NULL REFERENCES soc_users(id),
    consent_type VARCHAR(64) NOT NULL,
    consent_granted BOOLEAN NOT NULL DEFAULT TRUE,
    policy_version VARCHAR(32) NOT NULL DEFAULT '2026.03',
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_domain VARCHAR(64) UNIQUE NOT NULL,
    retention_days INTEGER NOT NULL,
    legal_basis VARCHAR(128) NOT NULL,
    purge_strategy VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID REFERENCES soc_users(id),
    event_type VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    source VARCHAR(128) NOT NULL,
    event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    title VARCHAR(160) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'Open',
    response_stage VARCHAR(32) NOT NULL DEFAULT 'Identification',
    affected_asset VARCHAR(120) NOT NULL DEFAULT 'unknown',
    owner_user_id UUID REFERENCES soc_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_incident_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES soc_incidents(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES soc_users(id),
    activity_type VARCHAR(64) NOT NULL,
    notes TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES soc_users(id),
    ip_address INET,
    endpoint VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS soc_risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID REFERENCES soc_users(id),
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    ip_reputation INTEGER NOT NULL DEFAULT 100,
    device_trust INTEGER NOT NULL DEFAULT 100,
    privilege_changes INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID REFERENCES soc_users(id),
    device_id VARCHAR(120) UNIQUE NOT NULL,
    device_type VARCHAR(64) NOT NULL,
    ip_address INET NOT NULL,
    location VARCHAR(128),
    login_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID REFERENCES soc_users(id),
    jwt_id VARCHAR(255) UNIQUE NOT NULL,
    device_id VARCHAR(120),
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'verified',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    event_id UUID REFERENCES soc_security_events(id),
    severity VARCHAR(16) NOT NULL,
    title VARCHAR(160) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'Open',
    source VARCHAR(128) NOT NULL DEFAULT 'threat-monitor',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    rule_name VARCHAR(160) NOT NULL,
    event_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    severity_level VARCHAR(16) NOT NULL,
    response_action VARCHAR(160) NOT NULL,
    tactic VARCHAR(128),
    technique VARCHAR(128),
    mitre_technique_id VARCHAR(32),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_threat_intel_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    indicator_type VARCHAR(32) NOT NULL,
    indicator_value VARCHAR(255) NOT NULL,
    provider VARCHAR(128) NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50,
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    incident_reference UUID REFERENCES soc_incidents(id),
    assigned_analyst UUID REFERENCES soc_users(id),
    investigation_notes TEXT NOT NULL DEFAULT '',
    evidence_files JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'Open',
    resolution_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    name VARCHAR(160) NOT NULL,
    trigger_event VARCHAR(128) NOT NULL,
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_posture_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    environment_name VARCHAR(128) NOT NULL,
    patch_status INTEGER NOT NULL DEFAULT 0,
    vulnerable_software INTEGER NOT NULL DEFAULT 0,
    inactive_security_controls INTEGER NOT NULL DEFAULT 0,
    unsecured_services INTEGER NOT NULL DEFAULT 0,
    posture_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_correlations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    correlation_name VARCHAR(160) NOT NULL,
    event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    incident_id UUID REFERENCES soc_incidents(id),
    severity VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_ai_anomaly_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    user_id UUID REFERENCES soc_users(id),
    device_id VARCHAR(120),
    event_id UUID REFERENCES soc_security_events(id),
    anomaly_type VARCHAR(128) NOT NULL,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    recommended_action VARCHAR(160) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_threat_hunt_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    created_by_user_id UUID REFERENCES soc_users(id),
    name VARCHAR(160) NOT NULL,
    description TEXT,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_threat_hunt_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    created_by_user_id UUID REFERENCES soc_users(id),
    query_id UUID REFERENCES soc_threat_hunt_queries(id),
    title VARCHAR(160) NOT NULL,
    summary TEXT NOT NULL,
    events_analyzed INTEGER NOT NULL DEFAULT 0,
    identified_threats JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_mitigations JSONB NOT NULL DEFAULT '[]'::jsonb,
    export_format VARCHAR(32) NOT NULL DEFAULT 'json',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_red_team_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES soc_tenants(id),
    scenario_name VARCHAR(160) NOT NULL,
    scenario_type VARCHAR(64) NOT NULL,
    mode VARCHAR(32) NOT NULL DEFAULT 'manual',
    intensity_level VARCHAR(16) NOT NULL DEFAULT 'Medium',
    duration_minutes INTEGER NOT NULL DEFAULT 5,
    target_user VARCHAR(255),
    target_device VARCHAR(120),
    training_mode BOOLEAN NOT NULL DEFAULT FALSE,
    scheduled_for TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'Planned',
    safety_status VARCHAR(32) NOT NULL DEFAULT 'Isolated',
    safety_notes TEXT NOT NULL DEFAULT 'Simulation restricted to lab-only telemetry.',
    expected_detection TEXT NOT NULL,
    scenario_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
    detection_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO soc_tenants (organization_id, name, status)
VALUES ('soc-cybe-default', 'SOC-CyBe Default Tenant', 'Active')
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO soc_roles (name, description)
VALUES
    ('Admin', 'Full administrative control'),
    ('SOC Analyst', 'Threat monitoring and triage'),
    ('Incident Responder', 'Response execution and containment'),
    ('Viewer', 'Read-only observation')
ON CONFLICT (name) DO NOTHING;

INSERT INTO soc_permissions (name, description)
VALUES
    ('dashboard:read', 'Read dashboard metrics'),
    ('incidents:read', 'View incidents'),
    ('incidents:write', 'Create and update incidents'),
    ('alerts:read', 'View alerts'),
    ('devices:read', 'View monitored devices'),
    ('logs:read', 'View audit logs'),
    ('users:manage', 'Manage users and roles')
ON CONFLICT (name) DO NOTHING;

INSERT INTO soc_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM soc_roles r
JOIN soc_permissions p ON (
    (r.name = 'Admin')
    OR (r.name = 'SOC Analyst' AND p.name IN ('dashboard:read', 'incidents:read', 'incidents:write', 'alerts:read', 'devices:read', 'logs:read'))
    OR (r.name = 'Incident Responder' AND p.name IN ('dashboard:read', 'incidents:read', 'incidents:write', 'alerts:read', 'devices:read'))
    OR (r.name = 'Viewer' AND p.name IN ('dashboard:read', 'incidents:read', 'alerts:read', 'devices:read'))
)
ON CONFLICT DO NOTHING;

INSERT INTO soc_retention_policies (data_domain, retention_days, legal_basis, purge_strategy)
VALUES
    ('audit_logs', 365, 'Security monitoring and regulatory review', 'Archive then purge'),
    ('security_events', 365, 'Threat detection and incident investigation', 'Archive then purge'),
    ('sessions', 90, 'Account security and anomaly review', 'Purge expired sessions'),
    ('incidents', 730, 'Incident response evidence retention', 'Archive immutable records'),
    ('consent_records', 1095, 'Privacy law accountability', 'Retain for regulatory evidence')
ON CONFLICT (data_domain) DO NOTHING;
