// Theme tokens. Every component reads CSS custom properties so a host can make
// the forms feel native by setting these once (via <ThemeProvider> or directly
// on a container). Two reference themes ship: `canticaWebTheme` (matches
// cantica-web's Vite app) and `studioTheme` (matches the studio webview's cs-*
// design language).

export interface SecureTheme {
  bg: string;
  surface: string;
  border: string;
  text: string;
  textMuted: string;
  accent: string;
  accentText: string;
  danger: string;
  warning: string;
  radius: string;
  fontFamily: string;
  fontSize: string;
}

export const TOKEN_NAMES: Record<keyof SecureTheme, string> = {
  bg: '--csec-bg',
  surface: '--csec-surface',
  border: '--csec-border',
  text: '--csec-text',
  textMuted: '--csec-text-muted',
  accent: '--csec-accent',
  accentText: '--csec-accent-text',
  danger: '--csec-danger',
  warning: '--csec-warning',
  radius: '--csec-radius',
  fontFamily: '--csec-font',
  fontSize: '--csec-font-size',
};

/** Turn a theme into an inline style object of CSS custom properties. */
export function themeToVars(theme: SecureTheme): Record<string, string> {
  const vars: Record<string, string> = {};
  (Object.keys(TOKEN_NAMES) as (keyof SecureTheme)[]).forEach((k) => {
    vars[TOKEN_NAMES[k]] = theme[k];
  });
  return vars;
}

/** cantica-web reference theme — light, rounded, sans. */
export const canticaWebTheme: SecureTheme = {
  bg: '#ffffff',
  surface: '#f7f8fa',
  border: '#e2e5ea',
  text: '#1a1d23',
  textMuted: '#6b7280',
  accent: '#4f46e5',
  accentText: '#ffffff',
  danger: '#dc2626',
  warning: '#d97706',
  radius: '8px',
  fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto, sans-serif',
  fontSize: '14px',
};

/** Studio webview reference theme — inherits VS Code theme variables where
 *  available, matching the cs-* look with tighter radii. */
export const studioTheme: SecureTheme = {
  bg: 'var(--vscode-editor-background, #1e1e1e)',
  surface: 'var(--vscode-editorWidget-background, #252526)',
  border: 'var(--vscode-widget-border, #3c3c3c)',
  text: 'var(--vscode-foreground, #cccccc)',
  textMuted: 'var(--vscode-descriptionForeground, #8c8c8c)',
  accent: 'var(--vscode-button-background, #0e639c)',
  accentText: 'var(--vscode-button-foreground, #ffffff)',
  danger: 'var(--vscode-errorForeground, #f14c4c)',
  warning: 'var(--vscode-editorWarning-foreground, #cca700)',
  radius: '3px',
  fontFamily: 'var(--vscode-font-family, system-ui, sans-serif)',
  fontSize: 'var(--vscode-font-size, 13px)',
};

export const THEMES: Record<string, SecureTheme> = {
  canticaWeb: canticaWebTheme,
  studio: studioTheme,
};
