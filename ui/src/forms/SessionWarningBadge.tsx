import React from 'react';

/** Renders a compact ⚠ badge for the current account warnings (spec AUTH F,
 *  X-Cantica-Warning). Hosts pass the latest warnings they observed. */
export function SessionWarningBadge({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <span className="csec-warning-badge" title={`Account warning: ${warnings.join(', ')}`} role="status">
      ⚠ {warnings.length === 1 ? warnings[0] : `${warnings.length} warnings`}
    </span>
  );
}
