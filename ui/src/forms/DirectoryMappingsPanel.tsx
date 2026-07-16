import React, { useEffect, useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, Input, Notice, Select } from '../primitives';
import type { DirectoryMapping } from '../types';

/** Directory group → role mapping (spec REGISTRATION B.pre.2). */
export function DirectoryMappingsPanel() {
  const { client } = useSecure();
  const [mappings, setMappings] = useState<DirectoryMapping[]>([]);
  const [roles, setRoles] = useState<string[]>([]);
  const [group, setGroup] = useState('');
  const [role, setRole] = useState('');
  const [error, setError] = useState<string | null>(null);

  const reload = React.useCallback(async () => {
    try {
      const [m, r] = await Promise.all([client.listMappings(), client.listRoles()]);
      setMappings(m);
      setRoles(r);
      if (!role && r.length) setRole(r[0]!);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load mappings');
    }
  }, [client, role]);

  useEffect(() => { void reload(); }, [reload]);

  async function guard(fn: () => Promise<unknown>) {
    setError(null);
    try { await fn(); await reload(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Action failed'); }
  }

  const effectiveRole = role || roles[0] || '';

  return (
    <div className="csec-panel">
      {error ? <Notice kind="error">{error}</Notice> : null}
      <p className="csec-hint">
        Users signing in through the enterprise directory receive the roles their groups map to.
        Groups that map to nothing get the default roles and a newbie flag for review.
      </p>

      {mappings.length === 0 ? <p className="csec-empty">No mappings yet — directory users land in limbo.</p> : null}

      {mappings.map((m) => (
        <div key={m.id} className="csec-mapping">
          <span className="csec-mapping-group">{m.external_group}</span>
          <span className="csec-role-badge">{m.role}</span>
          <Button variant="danger" onClick={() => void guard(() => client.removeMapping(m.id))}>✕</Button>
        </div>
      ))}

      <div className="csec-row">
        <Input
          placeholder="cn=studio-operators,dc=corp  /  groups-claim value"
          value={group}
          onChange={(e) => setGroup(e.target.value)}
        />
        <Select value={effectiveRole} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => <option key={r} value={r}>{r}</option>)}
        </Select>
        <Button
          variant="primary"
          disabled={!group.trim() || !effectiveRole}
          onClick={() => void guard(async () => { await client.addMapping(group.trim(), effectiveRole); setGroup(''); })}
        >Add</Button>
      </div>
    </div>
  );
}
