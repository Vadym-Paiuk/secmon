export default function StatCard({ label, value, sub, color }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '1px 18px',
      display: 'flex',
      flexDirection: 'column',
      gap: 1,
    }}>
      <span style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {label}
      </span>
      <span style={{ fontSize: 24, fontWeight: 600, color: color || 'var(--text)', fontFamily: 'var(--font-mono)' }}>
        {value ?? '—'}
      </span>
      {sub && <span style={{ color: 'var(--muted)', fontSize: 12 }}>{sub}</span>}
    </div>
  );
}
