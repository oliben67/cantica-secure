import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SecureProvider } from '../src/ThemeProvider';
import { LoginForm } from '../src/forms/LoginForm';
import { InviteRequestForm } from '../src/forms/InviteRequestForm';
import { AdminUsersPanel } from '../src/forms/AdminUsersPanel';
import { DirectoryMappingsPanel } from '../src/forms/DirectoryMappingsPanel';
import { ApiTokensPanel } from '../src/forms/ApiTokensPanel';
import { SessionWarningBadge } from '../src/forms/SessionWarningBadge';
import { studioTheme } from '../src/theme';
import { fakeTransport, ok, fail } from './fakeTransport';
import type { AdminUser } from '../src/types';

function wrap(node: React.ReactNode, transport: ReturnType<typeof fakeTransport>) {
  return render(<SecureProvider transport={transport} theme={studioTheme}>{node}</SecureProvider>);
}

const user = (over: Partial<AdminUser> = {}): AdminUser => ({
  id: 'u1', email: 'a@x.com', first_name: 'A', last_name: 'B', is_active: true,
  e_user_id: null, roles: ['viewer'], flags: [], created_at: 'n', updated_at: 'n', ...over,
});

// ── LoginForm ──────────────────────────────────────────────────────────────────

describe('LoginForm', () => {
  it('logs in and surfaces warnings', async () => {
    const t = fakeTransport({
      'POST /v1/auth/login': () => ok({ access_token: 'TK', token_type: 'bearer', expires_in: 3600, warnings: ['warning:none'] }),
    });
    let got: string | null = null;
    wrap(<LoginForm onSuccess={(r) => { got = r.access_token; }} />, t);
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@x.com' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(got).toBe('TK'));
    expect(screen.getByText('warning:none')).toBeInTheDocument();
  });

  it('shows the error detail on failure', async () => {
    const t = fakeTransport({ 'POST /v1/auth/login': () => fail(401, 'Invalid credentials') });
    wrap(<LoginForm />, t);
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@x.com' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'x' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument();
  });
});

// ── InviteRequestForm ────────────────────────────────────────────────────────────

describe('InviteRequestForm', () => {
  it('shows the token in in-band mode', async () => {
    const t = fakeTransport({ 'POST /v1/auth/invitations': () => ok({ invitation: 'INV.TOKEN' }) });
    let handed = '';
    wrap(<InviteRequestForm onInvitation={(tok) => { handed = tok; }} />, t);
    fireEvent.change(screen.getByLabelText('First name'), { target: { value: 'A' } });
    fireEvent.change(screen.getByLabelText('Last name'), { target: { value: 'B' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@x.com' } });
    fireEvent.click(screen.getByRole('button', { name: /request invitation/i }));
    expect(await screen.findByText('INV.TOKEN')).toBeInTheDocument();
    expect(handed).toBe('INV.TOKEN');
  });

  it('shows the generic message in mail-delivery mode', async () => {
    const t = fakeTransport({ 'POST /v1/auth/invitations': () => ok({ invitation: null }) });
    wrap(<InviteRequestForm />, t);
    fireEvent.change(screen.getByLabelText('First name'), { target: { value: 'A' } });
    fireEvent.change(screen.getByLabelText('Last name'), { target: { value: 'B' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@x.com' } });
    fireEvent.click(screen.getByRole('button', { name: /request invitation/i }));
    expect(await screen.findByText(/an invitation has been sent/i)).toBeInTheDocument();
  });
});

// ── AdminUsersPanel ──────────────────────────────────────────────────────────────

describe('AdminUsersPanel', () => {
  it('activates a newbie and filters via the checkbox', async () => {
    let activated = false;
    const t = fakeTransport({
      'GET /v1/users': () => ok([
        user({ id: 'act', email: 'active@x.com' }),
        user({ id: 'nb', email: 'newbie@x.com', is_active: false, flags: [{ id: 'f', flag: 'newbie', comment: '', created_by: '', created_at: 'n' }] }),
      ]),
      'POST /v1/users/nb/activate': () => { activated = true; return ok(user({ id: 'nb', is_active: true, flags: [] })); },
    });
    wrap(<AdminUsersPanel />, t);
    expect(await screen.findByText('newbie@x.com')).toBeInTheDocument();

    // Uncheck "show all" → only the newbie remains.
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.queryByText('active@x.com')).not.toBeInTheDocument();
    expect(screen.getByText('newbie@x.com')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
    await waitFor(() => expect(activated).toBe(true));
  });

  it('adds and removes a flag', async () => {
    const posted: string[] = [];
    const t = fakeTransport({
      'GET /v1/users': () => ok([user({ flags: [{ id: 'f1', flag: 'warning:none', comment: '', created_by: '', created_at: 'n' }] })]),
      'POST /v1/users/u1/flags': () => { posted.push('add'); return ok({ id: 'f2', flag: 'blocked:none', comment: '', created_by: '', created_at: 'n' }); },
      'DELETE /v1/users/u1/flags/f1': () => { posted.push('del'); return { ok: true, status: 204, data: null }; },
    });
    wrap(<AdminUsersPanel />, t);
    await screen.findByText('a@x.com');

    fireEvent.click(screen.getByRole('button', { name: 'remove warning:none' }));
    await waitFor(() => expect(posted).toContain('del'));

    fireEvent.click(screen.getByRole('button', { name: '+ Flag' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(posted).toContain('add'));
  });

  it('surfaces load errors', async () => {
    const t = fakeTransport({ 'GET /v1/users': () => fail(403, 'Requires one of: users:read') });
    wrap(<AdminUsersPanel />, t);
    expect(await screen.findByText(/users:read/)).toBeInTheDocument();
  });
});

// ── DirectoryMappingsPanel ───────────────────────────────────────────────────────

describe('DirectoryMappingsPanel', () => {
  it('lists, adds, and removes mappings', async () => {
    const actions: string[] = [];
    const t = fakeTransport({
      'GET /v1/directory/mappings': () => ok(actions.includes('add')
        ? [{ id: 'm1', external_group: 'cn=ops', role: 'operator', created_at: 'n' }]
        : []),
      'GET /v1/roles': () => ok([{ name: 'operator' }, { name: 'viewer' }]),
      'POST /v1/directory/mappings': () => { actions.push('add'); return ok({ id: 'm1', external_group: 'cn=ops', role: 'operator', created_at: 'n' }); },
      'DELETE /v1/directory/mappings/m1': () => { actions.push('del'); return { ok: true, status: 204, data: null }; },
    });
    wrap(<DirectoryMappingsPanel />, t);
    expect(await screen.findByText(/directory user/i)).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText(/groups-claim value/), { target: { value: 'cn=ops' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(actions).toContain('add'));
    expect(await screen.findByText('cn=ops')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '✕' }));
    await waitFor(() => expect(actions).toContain('del'));
  });
});

// ── ApiTokensPanel ───────────────────────────────────────────────────────────────

describe('ApiTokensPanel', () => {
  it('creates a token and reveals it once', async () => {
    const t = fakeTransport({
      'GET /v1/auth/tokens': () => ok([]),
      'POST /v1/auth/tokens': () => ok({ id: 't', name: 'ci', scopes: ['*'], expires_at: null, last_used_at: null, created_at: 'n', token: 'RAW-TOKEN' }),
    });
    wrap(<ApiTokensPanel />, t);
    await screen.findByText('No tokens.');
    fireEvent.change(screen.getByPlaceholderText('Token name'), { target: { value: 'ci' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('RAW-TOKEN')).toBeInTheDocument();
  });

  it('revokes a token', async () => {
    let revoked = false;
    const t = fakeTransport({
      'GET /v1/auth/tokens': () => ok(revoked ? [] : [{ id: 't', name: 'old', scopes: [], expires_at: null, last_used_at: null, created_at: 'n' }]),
      'DELETE /v1/auth/tokens/t': () => { revoked = true; return { ok: true, status: 204, data: null }; },
    });
    wrap(<ApiTokensPanel />, t);
    await screen.findByText('old');
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(revoked).toBe(true));
  });
});

// ── SessionWarningBadge + provider guard ─────────────────────────────────────────

describe('misc', () => {
  it('SessionWarningBadge renders nothing without warnings and a badge with them', () => {
    const { container, rerender } = render(<SessionWarningBadge warnings={[]} />);
    expect(container.firstChild).toBeNull();
    rerender(<SessionWarningBadge warnings={['warning:abuse']} />);
    expect(screen.getByText(/warning:abuse/)).toBeInTheDocument();
    rerender(<SessionWarningBadge warnings={['a', 'b']} />);
    expect(screen.getByText(/2 warnings/)).toBeInTheDocument();
  });
});
