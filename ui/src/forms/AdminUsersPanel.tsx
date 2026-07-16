import React, { useEffect, useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, FlagBadge, Input, Notice, Select } from '../primitives';
import { ASSIGNABLE_FLAGS, type AdminUser } from '../types';

/** User activation & flags (spec REGISTRATION C.pre.2 / A.4). The
 *  "show all users" checkbox mirrors the spec's auto-activated checkbox:
 *  unchecked narrows the list to newbie users awaiting activation. */
export function AdminUsersPanel() {
  const { client } = useSecure();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [showAll, setShowAll] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [flagFor, setFlagFor] = useState<string | null>(null);
  const [flagChoice, setFlagChoice] = useState<string>(ASSIGNABLE_FLAGS[0]);
  const [flagComment, setFlagComment] = useState('');

  const reload = React.useCallback(async () => {
    try {
      setUsers(await client.listUsers());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  const visible = showAll ? users : users.filter((u) => u.flags.some((f) => f.flag === 'newbie'));

  async function guard(fn: () => Promise<unknown>) {
    setError(null);
    try { await fn(); await reload(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Action failed'); }
  }

  return (
    <div className="csec-panel">
      {error ? <Notice kind="error">{error}</Notice> : null}
      <label className="csec-checkbox">
        <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
        Show all users
        <span className="csec-hint"> — uncheck to review new users awaiting activation</span>
      </label>

      {visible.length === 0 ? (
        <p className="csec-empty">{showAll ? 'No users.' : 'No users awaiting activation.'}</p>
      ) : null}

      {visible.map((u) => (
        <div key={u.id} className="csec-user">
          <div className="csec-user-head">
            <span className="csec-user-email">{u.email}</span>
            <span className="csec-hint">{u.roles.join(', ') || 'no roles'}</span>
            {!u.is_active ? (
              <Button variant="primary" onClick={() => void guard(() => client.activateUser(u.id))}>Enable</Button>
            ) : null}
            <Button onClick={() => { setFlagFor(flagFor === u.id ? null : u.id); setFlagComment(''); }}>+ Flag</Button>
          </div>
          <div className="csec-badges">
            <FlagBadge flag={u.is_active ? 'ok' : 'blocked:none'} />
            {u.e_user_id ? <span className="csec-flag csec-flag--ok">🏢 {u.e_user_id}</span> : null}
            {u.flags.map((f) => (
              <FlagBadge key={f.id} flag={f.flag} onRemove={() => void guard(() => client.removeFlag(u.id, f.id))} />
            ))}
          </div>
          {flagFor === u.id ? (
            <div className="csec-row">
              <Select value={flagChoice} onChange={(e) => setFlagChoice(e.target.value)}>
                {ASSIGNABLE_FLAGS.map((f) => <option key={f} value={f}>{f}</option>)}
              </Select>
              <Input placeholder="Comment (optional)" value={flagComment} onChange={(e) => setFlagComment(e.target.value)} />
              <Button variant="primary" onClick={() => void guard(async () => {
                await client.addFlag(u.id, flagChoice, flagComment.trim());
                setFlagFor(null);
              })}>Add</Button>
              <Button onClick={() => setFlagFor(null)}>Cancel</Button>
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}
