import React from 'react';

// Headless-friendly primitives styled purely via the theme's CSS custom
// properties (see theme.ts / styles.css). Hosts can override any csec-* class.

export function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="csec-field">
      <span className="csec-label">{label}{hint ? <span className="csec-hint"> — {hint}</span> : null}</span>
      {children}
    </label>
  );
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input(props, ref) {
    return <input ref={ref} className={`csec-input${props.className ? ` ${props.className}` : ''}`} {...props} />;
  },
);

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={`csec-select${props.className ? ` ${props.className}` : ''}`} {...props} />;
}

export function Button({
  variant = 'default', ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'danger' }) {
  return <button className={`csec-btn csec-btn--${variant}`} {...props} />;
}

export function Notice({ kind, children }: { kind: 'error' | 'warning' | 'info'; children: React.ReactNode }) {
  return <div className={`csec-notice csec-notice--${kind}`} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>;
}

export function FlagBadge({ flag, onRemove }: { flag: string; onRemove?: () => void }) {
  const kind = flag.startsWith('blocked') ? 'blocked' : flag.startsWith('warning') ? 'warning'
    : flag === 'newbie' ? 'newbie' : 'ok';
  return (
    <span className={`csec-flag csec-flag--${kind}`}>
      {flag}
      {onRemove ? <button type="button" className="csec-flag-x" aria-label={`remove ${flag}`} onClick={onRemove}>✕</button> : null}
    </span>
  );
}
