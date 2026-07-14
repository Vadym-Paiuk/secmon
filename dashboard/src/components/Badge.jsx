const COLORS = {
  blocked: { bg: '#2d1b1b', color: 'var(--danger)' },
  allowed: { bg: '#1b2d1b', color: 'var(--ok)' },
  alert:   { bg: '#2d2a1b', color: 'var(--warn)' },
  firewall:{ bg: '#1b2035', color: 'var(--accent)' },
  snort:   { bg: '#2a1b2d', color: '#c084fc' },
  av:      { bg: '#1b2d2d', color: '#34d399' },
  online:  { bg: '#1b2d1b', color: 'var(--ok)' },
  offline: { bg: '#2d1b1b', color: 'var(--danger)' },
};

export default function Badge({ text }) {
  const c = COLORS[text] || { bg: 'var(--border)', color: 'var(--muted)' };
  return (
    <span style={{
      background: c.bg,
      color: c.color,
      border: `1px solid ${c.color}33`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontFamily: 'var(--font-mono)',
      fontWeight: 500,
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
    }}>{text}</span>
  );
}
