import React, { createContext, useContext } from 'react';
import { type SecureTheme, canticaWebTheme, themeToVars } from './theme';
import { SecureClient } from './client';
import type { Transport } from './transport';

interface SecureContextValue {
  client: SecureClient;
  theme: SecureTheme;
}

const Ctx = createContext<SecureContextValue | null>(null);

/** Wraps the secure forms/panels: provides the client (built from a transport)
 *  and applies the theme tokens to a container div. Slot class overrides can be
 *  layered by passing `className`. */
export function SecureProvider({
  transport,
  theme = canticaWebTheme,
  className,
  children,
}: {
  transport: Transport;
  theme?: SecureTheme;
  className?: string;
  children: React.ReactNode;
}) {
  const client = React.useMemo(() => new SecureClient(transport), [transport]);
  return (
    <Ctx.Provider value={{ client, theme }}>
      <div className={`csec-root${className ? ` ${className}` : ''}`} style={themeToVars(theme) as React.CSSProperties}>
        {children}
      </div>
    </Ctx.Provider>
  );
}

export function useSecure(): SecureContextValue {
  const v = useContext(Ctx);
  if (v === null) throw new Error('useSecure must be used within a <SecureProvider>');
  return v;
}
