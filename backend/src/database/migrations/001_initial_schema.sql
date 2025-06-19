-- MedLinkPro Universal Medical Billing Platform
-- Multi-Tenant HIPAA-Compliant PostgreSQL Database Schema
-- Created: June 2025

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Create schemas for organization
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS integration;

-- Set default schema
SET search_path TO billing, public;

-- =============================================
-- CORE TENANT & PRACTICE MANAGEMENT
-- =============================================

-- Multi-tenant organizations (medical practices/groups)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('practice', 'group', 'hospital', 'clinic')),
    tax_id VARCHAR(20) UNIQUE NOT NULL, -- EIN for billing
    npi VARCHAR(10) UNIQUE, -- National Provider Identifier
    
    -- Contact Information
    phone VARCHAR(20),
    email CITEXT,
    website VARCHAR(255),
    
    -- Address
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(2),
    zip_code VARCHAR(10),
    country VARCHAR(2) DEFAULT 'US',
    
    -- Billing Configuration
    billing_provider VARCHAR(50), -- clearinghouse/payer
    edi_submitter_id VARCHAR(50),
    default_taxonomy_code VARCHAR(10),
    
    -- Subscription & Status
    subscription_tier VARCHAR(20) DEFAULT 'basic' CHECK (subscription_tier IN ('basic', 'professional', 'enterprise')),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Practice locations within organizations
CREATE TABLE practice_locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    name VARCHAR(255) NOT NULL,
    location_code VARCHAR(20), -- Internal identifier
    npi VARCHAR(10), -- Location-specific NPI
    
    -- Address
    address_line1 VARCHAR(255) NOT NULL,
    address_line2 VARCHAR(255),
    city VARCHAR(100) NOT NULL,
    state VARCHAR(2) NOT NULL,
    zip_code VARCHAR(10) NOT NULL,
    
    -- Contact
    phone VARCHAR(20),
    fax VARCHAR(20),
    email CITEXT,
    
    -- Configuration
    taxonomy_code VARCHAR(10),
    place_of_service_code VARCHAR(2), -- POS codes for billing
    
    is_primary BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- USER MANAGEMENT & AUTHENTICATION
-- =============================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Authentication
    email CITEXT UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Personal Information
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    title VARCHAR(50),
    
    -- Authorization
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'billing_manager', 'billing_specialist', 'provider', 'read_only')),
    permissions JSONB DEFAULT '{}',
    
    -- Status & Security
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    
    -- HIPAA Tracking
    hipaa_training_completed BOOLEAN DEFAULT FALSE,
    hipaa_training_date DATE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- PROVIDER MANAGEMENT
-- =============================================

CREATE TABLE providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Provider Identity
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    middle_initial VARCHAR(1),
    suffix VARCHAR(10),
    
    -- Professional Identifiers
    npi VARCHAR(10) UNIQUE NOT NULL,
    taxonomy_code VARCHAR(10) NOT NULL,
    license_number VARCHAR(50),
    dea_number VARCHAR(20),
    upin VARCHAR(10), -- Legacy identifier
    
    -- Specialties
    primary_specialty VARCHAR(100),
    secondary_specialties TEXT[],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_billing_provider BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- PATIENT MANAGEMENT (HIPAA COMPLIANT)
-- =============================================

CREATE TABLE patients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Patient Identity (Encrypted PHI)
    medical_record_number VARCHAR(50), -- MRN
    
    -- Demographics (Encrypted)
    first_name_encrypted BYTEA NOT NULL,
    last_name_encrypted BYTEA NOT NULL,
    middle_name_encrypted BYTEA,
    date_of_birth_encrypted BYTEA NOT NULL,
    gender VARCHAR(1) CHECK (gender IN ('M', 'F', 'U')),
    
    -- Contact Information (Encrypted)
    phone_encrypted BYTEA,
    email_encrypted BYTEA,
    
    -- Address (Encrypted)
    address_line1_encrypted BYTEA,
    address_line2_encrypted BYTEA,
    city_encrypted BYTEA,
    state VARCHAR(2),
    zip_code VARCHAR(10),
    
    -- Additional Demographics
    marital_status VARCHAR(1) CHECK (marital_status IN ('S', 'M', 'D', 'W', 'U')),
    race VARCHAR(50),
    ethnicity VARCHAR(50),
    preferred_language VARCHAR(50) DEFAULT 'English',
    
    -- Emergency Contact (Encrypted)
    emergency_contact_name_encrypted BYTEA,
    emergency_contact_phone_encrypted BYTEA,
    emergency_contact_relationship VARCHAR(50),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    deceased_date DATE,
    
    -- Search helpers (hashed for indexing)
    first_name_hash VARCHAR(64),
    last_name_hash VARCHAR(64),
    dob_hash VARCHAR(64),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes on hashed fields for search
CREATE INDEX idx_patients_first_name_hash ON patients(first_name_hash);
CREATE INDEX idx_patients_last_name_hash ON patients(last_name_hash);
CREATE INDEX idx_patients_dob_hash ON patients(dob_hash);
CREATE INDEX idx_patients_org_active ON patients(organization_id, is_active);

-- =============================================
-- INSURANCE & COVERAGE
-- =============================================

CREATE TABLE insurance_payers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    name VARCHAR(255) NOT NULL,
    payer_id VARCHAR(50) UNIQUE NOT NULL, -- Electronic payer ID
    
    -- Contact Information
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(2),
    zip_code VARCHAR(10),
    
    phone VARCHAR(20),
    claims_phone VARCHAR(20),
    website VARCHAR(255),
    
    -- Electronic Processing
    edi_payer_id VARCHAR(50),
    supports_electronic_claims BOOLEAN DEFAULT TRUE,
    supports_electronic_era BOOLEAN DEFAULT TRUE,
    
    -- Configuration
    claim_submission_format VARCHAR(20) DEFAULT '837P',
    days_to_pay INTEGER DEFAULT 30,
    
    is_active BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE patient_insurance (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    payer_id UUID NOT NULL REFERENCES insurance_payers(id),
    
    -- Coverage Details
    policy_number_encrypted BYTEA NOT NULL,
    group_number_encrypted BYTEA,
    
    -- Priority
    coverage_order INTEGER NOT NULL CHECK (coverage_order IN (1, 2, 3)), -- Primary, Secondary, Tertiary
    
    -- Coverage Period
    effective_date DATE NOT NULL,
    termination_date DATE,
    
    -- Subscriber Information (if different from patient)
    subscriber_id_encrypted BYTEA,
    subscriber_first_name_encrypted BYTEA,
    subscriber_last_name_encrypted BYTEA,
    subscriber_dob_encrypted BYTEA,
    subscriber_gender VARCHAR(1),
    
    relationship_to_subscriber VARCHAR(20) DEFAULT 'self',
    
    -- Coverage Details
    copay_amount DECIMAL(10,2),
    deductible_amount DECIMAL(10,2),
    out_of_pocket_max DECIMAL(10,2),
    
    -- Authorization
    requires_authorization BOOLEAN DEFAULT FALSE,
    authorization_phone VARCHAR(20),
    
    is_active BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(patient_id, coverage_order, effective_date)
);

-- =============================================
-- CLAIMS MANAGEMENT
-- =============================================

CREATE TABLE claims (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    patient_id UUID NOT NULL REFERENCES patients(id),
    provider_id UUID NOT NULL REFERENCES providers(id),
    practice_location_id UUID REFERENCES practice_locations(id),
    insurance_id UUID NOT NULL REFERENCES patient_insurance(id),
    
    -- Claim Identity
    claim_number VARCHAR(50) UNIQUE NOT NULL, -- Internal claim number
    icn VARCHAR(50), -- Insurance Control Number (from payer)
    
    -- Service Information
    service_date_from DATE NOT NULL,
    service_date_to DATE NOT NULL,
    
    -- Billing Information
    total_charges DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    total_payments DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    total_adjustments DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    patient_responsibility DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    
    -- Claim Status
    status VARCHAR(30) NOT NULL DEFAULT 'draft' CHECK (
        status IN ('draft', 'ready', 'submitted', 'accepted', 'rejected', 'paid', 'denied', 'appeal')
    ),
    
    -- Submission Information
    submitted_at TIMESTAMP WITH TIME ZONE,
    submission_method VARCHAR(20) CHECK (submission_method IN ('electronic', 'paper', 'clearinghouse')),
    batch_id VARCHAR(50),
    
    -- Processing Information
    processed_at TIMESTAMP WITH TIME ZONE,
    paid_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional Information
    place_of_service VARCHAR(2),
    claim_type VARCHAR(10) DEFAULT 'CMS1500' CHECK (claim_type IN ('CMS1500', 'UB04')),
    frequency_code VARCHAR(1) DEFAULT '1', -- Original, Corrected, etc.
    
    -- Notes and References
    notes TEXT,
    external_claim_id VARCHAR(50), -- From clearinghouse/payer
    
    -- Tracking
    created_by UUID REFERENCES users(id),
    last_modified_by UUID REFERENCES users(id),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Claim line items (procedures/services)
CREATE TABLE claim_lines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    
    -- Service Details
    line_number INTEGER NOT NULL,
    procedure_code VARCHAR(10) NOT NULL, -- CPT/HCPCS code
    modifier_1 VARCHAR(2),
    modifier_2 VARCHAR(2),
    modifier_3 VARCHAR(2),
    modifier_4 VARCHAR(2),
    
    -- Diagnosis
    diagnosis_pointer VARCHAR(4), -- Points to diagnosis on claim
    
    -- Service Information
    service_date DATE NOT NULL,
    units INTEGER NOT NULL DEFAULT 1,
    
    -- Financial
    charges DECIMAL(10,2) NOT NULL,
    allowed_amount DECIMAL(10,2),
    paid_amount DECIMAL(10,2) DEFAULT 0.00,
    adjustment_amount DECIMAL(10,2) DEFAULT 0.00,
    
    -- Place of Service
    place_of_service VARCHAR(2),
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(claim_id, line_number)
);

-- Diagnosis codes for claims
CREATE TABLE claim_diagnoses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    
    diagnosis_code VARCHAR(10) NOT NULL, -- ICD-10 code
    diagnosis_pointer INTEGER NOT NULL CHECK (diagnosis_pointer BETWEEN 1 AND 12),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(claim_id, diagnosis_pointer)
);

-- =============================================
-- PAYMENTS & ERA PROCESSING
-- =============================================

CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    payer_id UUID REFERENCES insurance_payers(id),
    
    -- Payment Identity
    payment_number VARCHAR(50),
    check_number VARCHAR(50),
    trace_number VARCHAR(50),
    
    -- Payment Details
    payment_date DATE NOT NULL,
    payment_amount DECIMAL(12,2) NOT NULL,
    payment_method VARCHAR(20) CHECK (payment_method IN ('EFT', 'check', 'credit_card', 'cash')),
    
    -- ERA Information
    era_filename VARCHAR(255),
    era_processed_at TIMESTAMP WITH TIME ZONE,
    
    -- Status
    status VARCHAR(20) DEFAULT 'received' CHECK (status IN ('received', 'applied', 'deposited')),
    
    -- Notes
    notes TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE payment_details (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
    claim_id UUID REFERENCES claims(id),
    claim_line_id UUID REFERENCES claim_lines(id),
    
    -- Payment Information
    paid_amount DECIMAL(10,2) NOT NULL,
    adjustment_amount DECIMAL(10,2) DEFAULT 0.00,
    
    -- Reason Codes
    adjustment_reason_code VARCHAR(10),
    adjustment_reason_description TEXT,
    remark_codes VARCHAR(50)[],
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- REPORTING & ANALYTICS
-- =============================================

CREATE TABLE billing_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    report_type VARCHAR(50) NOT NULL,
    report_name VARCHAR(255) NOT NULL,
    
    -- Parameters
    date_from DATE,
    date_to DATE,
    filters JSONB DEFAULT '{}',
    
    -- Report Data
    report_data JSONB,
    
    -- Metadata
    generated_by UUID REFERENCES users(id),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- EMR INTEGRATION (i-Heal specific)
-- =============================================

CREATE SCHEMA integration;

CREATE TABLE integration.emr_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES billing.organizations(id) ON DELETE CASCADE,
    
    emr_system VARCHAR(50) NOT NULL, -- 'iheal', 'epic', 'cerner', etc.
    
    -- Connection Details
    api_endpoint VARCHAR(255),
    api_key_encrypted BYTEA,
    client_id VARCHAR(100),
    
    -- Sync Configuration
    sync_patients BOOLEAN DEFAULT TRUE,
    sync_appointments BOOLEAN DEFAULT TRUE,
    sync_procedures BOOLEAN DEFAULT TRUE,
    sync_diagnoses BOOLEAN DEFAULT TRUE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(20) DEFAULT 'pending',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE integration.sync_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connection_id UUID NOT NULL REFERENCES integration.emr_connections(id) ON DELETE CASCADE,
    
    sync_type VARCHAR(50) NOT NULL, -- 'patients', 'appointments', etc.
    status VARCHAR(20) NOT NULL CHECK (status IN ('started', 'completed', 'failed')),
    
    records_processed INTEGER DEFAULT 0,
    records_successful INTEGER DEFAULT 0,
    records_failed INTEGER DEFAULT 0,
    
    error_message TEXT,
    sync_data JSONB,
    
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- =============================================
-- AUDIT TRAIL (HIPAA COMPLIANCE)
-- =============================================

CREATE SCHEMA audit;

CREATE TABLE audit.access_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES billing.users(id),
    organization_id UUID REFERENCES billing.organizations(id),
    
    -- Access Details
    action VARCHAR(50) NOT NULL, -- 'view', 'create', 'update', 'delete', 'login', 'logout'
    resource_type VARCHAR(50), -- 'patient', 'claim', 'payment', etc.
    resource_id UUID,
    
    -- Request Information  
    ip_address INET,
    user_agent TEXT,
    endpoint VARCHAR(255),
    http_method VARCHAR(10),
    
    -- PHI Access (for HIPAA)
    phi_accessed BOOLEAN DEFAULT FALSE,
    patient_id UUID,
    
    -- Result
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for audit log queries
CREATE INDEX idx_audit_access_logs_user_time ON audit.access_logs(user_id, created_at);
CREATE INDEX idx_audit_access_logs_patient_time ON audit.access_logs(patient_id, created_at) WHERE patient_id IS NOT NULL;
CREATE INDEX idx_audit_access_logs_org_time ON audit.access_logs(organization_id, created_at);

-- =============================================
-- TRIGGERS & FUNCTIONS
-- =============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers to main tables
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_patients_updated_at BEFORE UPDATE ON patients 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_claims_updated_at BEFORE UPDATE ON claims 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to create audit log entries
CREATE OR REPLACE FUNCTION create_audit_log() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.access_logs (
        user_id, 
        organization_id, 
        action, 
        resource_type, 
        resource_id,
        phi_accessed,
        patient_id
    ) VALUES (
        COALESCE(current_setting('app.current_user_id', true)::UUID, NULL),
        COALESCE(current_setting('app.current_org_id', true)::UUID, NULL),
        TG_OP,
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        TG_TABLE_NAME = 'patients',
        CASE WHEN TG_TABLE_NAME = 'patients' THEN COALESCE(NEW.id, OLD.id) ELSE NULL END
    );
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Apply audit triggers to sensitive tables
CREATE TRIGGER audit_patients_changes 
    AFTER INSERT OR UPDATE OR DELETE ON patients
    FOR EACH ROW EXECUTE FUNCTION create_audit_log();

CREATE TRIGGER audit_claims_changes 
    AFTER INSERT OR UPDATE OR DELETE ON claims
    FOR EACH ROW EXECUTE FUNCTION create_audit_log();

-- =============================================
-- INDEXES FOR PERFORMANCE
-- =============================================

-- Organizations
CREATE INDEX idx_organizations_status ON organizations(status);
CREATE INDEX idx_organizations_type ON organizations(type);

-- Users
CREATE INDEX idx_users_org_active ON users(organization_id, is_active);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- Providers
CREATE INDEX idx_providers_org_active ON providers(organization_id, is_active);
CREATE INDEX idx_providers_npi ON providers(npi);

-- Claims
CREATE INDEX idx_claims_org_status ON claims(organization_id, status);
CREATE INDEX idx_claims_patient ON claims(patient_id);
CREATE INDEX idx_claims_provider ON claims(provider_id);
CREATE INDEX idx_claims_service_date ON claims(service_date_from, service_date_to);
CREATE INDEX idx_claims_submitted ON claims(submitted_at) WHERE submitted_at IS NOT NULL;

-- Claim Lines
CREATE INDEX idx_claim_lines_claim ON claim_lines(claim_id);
CREATE INDEX idx_claim_lines_procedure ON claim_lines(procedure_code);

-- Payments
CREATE INDEX idx_payments_org_date ON payments(organization_id, payment_date);
CREATE INDEX idx_payments_payer ON payments(payer_id);
CREATE INDEX idx_payment_details_claim ON payment_details(claim_id);

-- Insurance
CREATE INDEX idx_patient_insurance_patient ON patient_insurance(patient_id, coverage_order);
CREATE INDEX idx_patient_insurance_active ON patient_insurance(patient_id, is_active);

-- =============================================
-- ROW LEVEL SECURITY (RLS)
-- =============================================

-- Enable RLS on all tenant-specific tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE patients ENABLE ROW LEVEL SECURITY;
ALTER TABLE providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;

-- RLS Policy for organizations (users can only see their own org)
CREATE POLICY org_isolation_policy ON organizations
    FOR ALL
    TO authenticated_users
    USING (id = current_setting('app.current_org_id')::UUID);

-- RLS Policy for users (users can only see users in their org)
CREATE POLICY user_org_isolation_policy ON users
    FOR ALL  
    TO authenticated_users
    USING (organization_id = current_setting('app.current_org_id')::UUID);

-- RLS Policy for patients (users can only see patients in their org)
CREATE POLICY patient_org_isolation_policy ON patients
    FOR ALL
    TO authenticated_users
    USING (organization_id = current_setting('app.current_org_id')::UUID);

-- Similar policies for other tables...
CREATE POLICY provider_org_isolation_policy ON providers
    FOR ALL
    TO authenticated_users
    USING (organization_id = current_setting('app.current_org_id')::UUID);

CREATE POLICY claim_org_isolation_policy ON claims
    FOR ALL
    TO authenticated_users
    USING (organization_id = current_setting('app.current_org_id')::UUID);

CREATE POLICY payment_org_isolation_policy ON payments
    FOR ALL
    TO authenticated_users  
    USING (organization_id = current_setting('app.current_org_id')::UUID);

-- =============================================
-- INITIAL DATA SETUP
-- =============================================

-- Insert common insurance payers
INSERT INTO insurance_payers (name, payer_id, edi_payer_id, supports_electronic_claims) VALUES
('Medicare', 'MEDICARE', '00120', true),
('Medicaid', 'MEDICAID', '00140', true),
('Blue Cross Blue Shield', 'BCBS', '00510', true),
('Aetna', 'AETNA', '00431', true),
('Cigna', 'CIGNA', '00510', true),
('UnitedHealthcare', 'UHC', '00431', true),
('Humana', 'HUMANA', '00431', true);

-- Create database role for the application
CREATE ROLE medlinkpro_app WITH LOGIN PASSWORD 'secure_password_here';
CREATE ROLE authenticated_users;
GRANT authenticated_users TO medlinkpro_app;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA billing TO medlinkpro_app;
GRANT USAGE ON SCHEMA audit TO medlinkpro_app;
GRANT USAGE ON SCHEMA integration TO medlinkpro_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA billing TO medlinkpro_app;
GRANT INSERT ON ALL TABLES IN SCHEMA audit TO medlinkpro_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA integration TO medlinkpro_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA billing TO medlinkpro_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO medlinkpro_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA integration TO medlinkpro_app;

-- =============================================
-- VIEWS FOR COMMON QUERIES
-- =============================================

-- Active claims with patient and provider info
CREATE VIEW active_claims_view AS
SELECT 
    c.id,
    c.claim_number,
    c.status,
    c.service_date_from,
    c.service_date_to,
    c.total_charges,
    c.total_payments,
    c.patient_responsibility,
    p.first_name_encrypted,
    p.last_name_encrypted,
    pr.first_name as provider_first_name,
    pr.last_name as provider_last_name,
    ip.name as payer_name
FROM claims c
JOIN patients p ON c.patient_id = p.id
JOIN providers pr ON c.provider_id = pr.id
JOIN patient_insurance pi ON c.insurance_id = pi.id
JOIN insurance_payers ip ON pi.payer_id = ip.id
WHERE c.status IN ('submitted', 'accepted', 'rejected');

-- Revenue summary by month
CREATE VIEW monthly_revenue_view AS
SELECT 
    DATE_TRUNC('month', service_date_from) as month,
    organization_id,
    COUNT(*) as claim_count,
    SUM(total_charges) as total_charges,
    SUM(total_payments) as total_payments,
    SUM(patient_responsibility) as patient_responsibility
FROM claims
WHERE status = 'paid'
GROUP BY DATE_TRUNC('month', service_date_from), organization_id;

-- =============================================
-- COMMENTS FOR DOCUMENTATION
-- =============================================

COMMENT ON SCHEMA billing IS 'Core medical billing and practice management tables';
COMMENT ON SCHEMA audit IS 'HIPAA audit trail and access logging';
COMMENT ON SCHEMA integration IS 'EMR integration and data synchronization';

COMMENT ON TABLE organizations IS 'Multi-tenant medical practices and healthcare organizations';
COMMENT ON TABLE patients IS 'Patient demographics with encrypted PHI for HIPAA compliance';
COMMENT ON TABLE claims IS 'Medical billing claims (CMS-1500/UB-04)';
COMMENT ON TABLE payments IS 'Insurance payments and ERA processing';
COMMENT ON TABLE audit.access_logs IS 'HIPAA-compliant audit trail for all system access';

-- Schema creation complete
SELECT 'MedLinkPro Database Schema Created Successfully!' as status;