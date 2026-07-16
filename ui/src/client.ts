// Typed client over a Transport — the surface the forms/panels call.

import type { Transport } from './transport';
import type {
  AdminUser, ApiTokenInfo, DirectoryMapping, LoginResult, UiConfig, UserFlag,
} from './types';

export class SecureClient {
  private readonly transport: Transport;
  constructor(transport: Transport) {
    this.transport = transport;
  }

  private async unwrap<T>(p: ReturnType<Transport['send']>): Promise<T> {
    const res = await p;
    if (!res.ok) {
      const detail = (res.data as { detail?: string } | null)?.detail ?? `HTTP ${res.status}`;
      throw new SecureError(detail, res.status);
    }
    return res.data as T;
  }

  uiConfig(): Promise<UiConfig> {
    return this.unwrap(this.transport.send({ method: 'GET', path: '/v1/security/ui-config' }));
  }

  // ── auth ──
  login(email: string, password: string): Promise<LoginResult> {
    return this.unwrap(this.transport.send({ method: 'POST', path: '/v1/auth/login', body: { email, password } }));
  }
  oidcLogin(idToken: string): Promise<LoginResult> {
    return this.unwrap(this.transport.send({ method: 'POST', path: '/v1/auth/oidc', body: { id_token: idToken } }));
  }
  requestInvitation(firstName: string, lastName: string, email: string): Promise<{ invitation: string | null }> {
    return this.unwrap(this.transport.send({
      method: 'POST', path: '/v1/auth/invitations',
      body: { first_name: firstName, last_name: lastName, email },
    }));
  }
  enrolKey(assertion: string, publicKeyPem: string): Promise<{ cantica_user_id: string }> {
    return this.unwrap(this.transport.send({
      method: 'POST', path: '/v1/auth/register', body: { assertion, public_key_pem: publicKeyPem },
    }));
  }
  assert(assertion: string): Promise<LoginResult> {
    return this.unwrap(this.transport.send({ method: 'POST', path: '/v1/auth/assert', body: { assertion } }));
  }

  // ── api tokens ──
  listTokens(): Promise<ApiTokenInfo[]> {
    return this.unwrap(this.transport.send({ method: 'GET', path: '/v1/auth/tokens', auth: true }));
  }
  createToken(name: string, scopes: string[], expiresDays?: number): Promise<ApiTokenInfo & { token: string }> {
    return this.unwrap(this.transport.send({
      method: 'POST', path: '/v1/auth/tokens', auth: true,
      body: { name, scopes, ...(expiresDays !== undefined ? { expires_days: expiresDays } : {}) },
    }));
  }
  deleteToken(id: string): Promise<void> {
    return this.unwrap(this.transport.send({ method: 'DELETE', path: `/v1/auth/tokens/${encodeURIComponent(id)}`, auth: true }));
  }

  // ── admin: users / flags / activation ──
  listUsers(flag?: string): Promise<AdminUser[]> {
    const q = flag ? `?flag=${encodeURIComponent(flag)}` : '';
    return this.unwrap(this.transport.send({ method: 'GET', path: `/v1/users${q}`, auth: true }));
  }
  activateUser(id: string): Promise<AdminUser> {
    return this.unwrap(this.transport.send({ method: 'POST', path: `/v1/users/${encodeURIComponent(id)}/activate`, auth: true }));
  }
  addFlag(userId: string, flag: string, comment = ''): Promise<UserFlag> {
    return this.unwrap(this.transport.send({
      method: 'POST', path: `/v1/users/${encodeURIComponent(userId)}/flags`, auth: true, body: { flag, comment },
    }));
  }
  removeFlag(userId: string, flagId: string): Promise<void> {
    return this.unwrap(this.transport.send({
      method: 'DELETE', path: `/v1/users/${encodeURIComponent(userId)}/flags/${encodeURIComponent(flagId)}`, auth: true,
    }));
  }
  listRoles(): Promise<string[]> {
    return this.unwrap<Array<{ name: string }>>(
      this.transport.send({ method: 'GET', path: '/v1/roles', auth: true }),
    ).then((roles) => roles.map((r) => r.name));
  }

  // ── admin: directory mappings ──
  listMappings(): Promise<DirectoryMapping[]> {
    return this.unwrap(this.transport.send({ method: 'GET', path: '/v1/directory/mappings', auth: true }));
  }
  addMapping(externalGroup: string, roleName: string): Promise<DirectoryMapping> {
    return this.unwrap(this.transport.send({
      method: 'POST', path: '/v1/directory/mappings', auth: true,
      body: { external_group: externalGroup, role_name: roleName },
    }));
  }
  removeMapping(id: string): Promise<void> {
    return this.unwrap(this.transport.send({ method: 'DELETE', path: `/v1/directory/mappings/${encodeURIComponent(id)}`, auth: true }));
  }
}

export class SecureError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = 'SecureError';
  }
}
