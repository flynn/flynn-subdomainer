CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE FUNCTION set_updated_at_column() RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC';
    RETURN NEW;
  END;
$$ language 'plpgsql';

CREATE SEQUENCE domain_seeds;

CREATE TABLE domains (
  domain_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  domain text UNIQUE NOT NULL,
  creator_ip text NOT NULL,
  access_key bytea NOT NULL,
  nameservers json,
  external_change_id text,
  external_change_applied BOOLEAN NOT NULL default false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TRIGGER set_updated_at_domains
  BEFORE UPDATE ON domains FOR EACH ROW
  EXECUTE PROCEDURE set_updated_at_column()
