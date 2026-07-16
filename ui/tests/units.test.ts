import { describe, it, expect, vi } from 'vitest';
import { SecureClient, SecureError } from '../src/client';
import { createFetchTransport, createBridgeTransport } from '../src/transport';
import { themeToVars, canticaWebTheme, studioTheme, TOKEN_NAMES } from '../src/theme';
import { generateKeyPair, createEnrolmentAssertion, createAuthAssertion } from '../src/keys';
import { fakeTransport, ok, fail } from './fakeTransport';

// ── client ────────────────────────────────────────────────────────────────────

describe('SecureClient', () => {
  it('unwraps ok responses and maps roles', async () => {
    const t = fakeTransport({
      'GET /v1/roles': () => ok([{ name: 'admin' }, { name: 'viewer' }]),
    });
    const client = new SecureClient(t);
    expect(await client.listRoles()).toEqual(['admin', 'viewer']);
    expect(t.calls[0]!.auth).toBe(true);
  });

  it('throws SecureError with the server detail on failure', async () => {
    const t = fakeTransport({ 'POST /v1/auth/login': () => fail(401, 'Invalid credentials') });
    const client = new SecureClient(t);
    await expect(client.login('a@x.com', 'pw')).rejects.toMatchObject({
      name: 'SecureError', status: 401, message: 'Invalid credentials',
    });
  });

  it('falls back to HTTP status when no detail', async () => {
    const t = fakeTransport({ 'GET /v1/users': () => ({ ok: false, status: 500, data: null }) });
    await expect(new SecureClient(t).listUsers()).rejects.toBeInstanceOf(SecureError);
  });

  it('builds flag query and token endpoints', async () => {
    const t = fakeTransport({
      'GET /v1/users': () => ok([]),
      'POST /v1/auth/tokens': () => ok({ id: 't', name: 'ci', scopes: [], expires_at: null, last_used_at: null, created_at: 'now', token: 'raw' }),
      'DELETE /v1/auth/tokens/t': () => ({ ok: true, status: 204, data: null }),
    });
    const client = new SecureClient(t);
    await client.listUsers('newbie');
    expect(t.calls[0]!.path).toBe('/v1/users?flag=newbie');
    const created = await client.createToken('ci', ['*'], 7);
    expect(created.token).toBe('raw');
    await client.deleteToken('t');
    expect(t.calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/v1/auth/tokens/t' });
  });
});

// ── fetch transport ────────────────────────────────────────────────────────────

describe('createFetchTransport', () => {
  it('adds bearer token for authed requests and reads the warning header', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ok: 1 }), {
      status: 200, headers: { 'X-Cantica-Warning': 'warning:abuse' },
    })) as unknown as typeof fetch;
    const t = createFetchTransport({ baseUrl: 'http://h/', getToken: () => 'TKN', fetchImpl });
    const res = await t.send({ method: 'GET', path: '/v1/me', auth: true });
    expect(res.warning).toBe('warning:abuse');
    const init = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0]![1];
    expect(init.headers.Authorization).toBe('Bearer TKN');
  });

  it('omits auth header when not requested', async () => {
    const fetchImpl = vi.fn(async () => new Response('null', { status: 200 })) as unknown as typeof fetch;
    const t = createFetchTransport({ baseUrl: 'http://h', getToken: () => 'TKN', fetchImpl });
    await t.send({ method: 'GET', path: '/v1/prompts' });
    const init = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0]![1];
    expect(init.headers.Authorization).toBeUndefined();
  });
});

// ── bridge transport ────────────────────────────────────────────────────────────

describe('createBridgeTransport', () => {
  it('resolves when the host posts a matching response', async () => {
    let handler: ((m: unknown) => void) | null = null;
    const posted: unknown[] = [];
    const t = createBridgeTransport({
      post: (m) => posted.push(m),
      subscribe: (h) => { handler = h; return () => {}; },
    });
    const p = t.send({ method: 'GET', path: '/v1/roles', auth: true });
    const req = posted[0] as { id: number };
    handler!({ type: 'secure:response', id: req.id, response: ok([{ name: 'admin' }]) });
    expect((await p).data).toEqual([{ name: 'admin' }]);
  });

  it('rejects on timeout', async () => {
    vi.useFakeTimers();
    const t = createBridgeTransport({ post: () => {}, subscribe: () => () => {}, timeoutMs: 100 });
    const p = t.send({ method: 'GET', path: '/x' });
    const assertion = expect(p).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(200);
    await assertion;
    vi.useRealTimers();
  });
});

// ── theme ──────────────────────────────────────────────────────────────────────

describe('theme', () => {
  it('maps every token to a --csec-* var', () => {
    const vars = themeToVars(canticaWebTheme);
    for (const name of Object.values(TOKEN_NAMES)) expect(vars[name]).toBeDefined();
    expect(vars['--csec-accent']).toBe(canticaWebTheme.accent);
  });

  it('studio theme uses VS Code variables', () => {
    expect(studioTheme.text).toContain('--vscode-foreground');
  });
});

// ── keys ────────────────────────────────────────────────────────────────────────

describe('keys', () => {
  it('generates a public-key PEM and signs RS256 assertions', async () => {
    const { privateKey, publicKeyPem } = await generateKeyPair();
    expect(publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(publicKeyPem).not.toContain('PRIVATE');

    const enrol = await createEnrolmentAssertion(privateKey, 'client-1', 'INVITE.JWT');
    const payload = enrol.split('.')[1]!;
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    expect(claims.invitation).toBe('INVITE.JWT');
    expect(claims.jti).toBeTruthy();
    expect(claims.exp - claims.iat).toBe(300);

    const auth = await createAuthAssertion(privateKey, 'user@x.com');
    const authClaims = JSON.parse(atob(auth.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')));
    expect(authClaims.sub).toBe('user@x.com');
  });
});
