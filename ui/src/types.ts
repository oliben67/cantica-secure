// Shared types — mirror the cantica-secure API contract.

export interface UiConfig {
  app_name: string;
  local_mode: boolean;
  auth_backend: string;
  features: {
    password_login: boolean;
    oidc_login: boolean;
    invitations: boolean;
    key_enrolment: boolean;
    anonymous_access: boolean;
    auto_activate_users: boolean;
    mail_delivery: boolean;
  };
}

export interface UserFlag {
  id: string;
  flag: string;
  comment: string;
  created_by: string;
  created_at: string;
}

export interface AdminUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  e_user_id: string | null;
  roles: string[];
  flags: UserFlag[];
  created_at: string;
  updated_at: string;
}

export interface DirectoryMapping {
  id: string;
  external_group: string;
  role: string;
  created_at: string;
}

export interface LoginResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  warnings: string[];
}

export interface ApiTokenInfo {
  id: string;
  name: string;
  scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

/** Assignable flags (blocked / warning families + housekeeping) — mirrors core/flags.py. */
export const ASSIGNABLE_FLAGS = [
  'warning:abuse', 'warning:suspicious', 'warning:none',
  'blocked:abuse', 'blocked:suspicious', 'blocked:none',
  'pending:roles', 'ok',
] as const;
