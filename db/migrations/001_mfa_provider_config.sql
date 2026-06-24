CREATE TABLE IF NOT EXISTS did.ad_mfa_provider_config (
    org_id     int          PRIMARY KEY,
    provider   varchar(32)  NOT NULL DEFAULT 'expo',
    config     text         NOT NULL DEFAULT '{}',  -- AES-GCM encrypted JSON
    created_at timestamptz  NOT NULL DEFAULT now(),
    updated_at timestamptz  NOT NULL DEFAULT now()
);
