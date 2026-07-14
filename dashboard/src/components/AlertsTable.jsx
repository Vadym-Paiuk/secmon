function fmt(ts) {
  return new Date(ts).toLocaleString('uk-UA', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

export default function AlertsTable({ alerts }) {
  if (!alerts.length) return (
    <p style={{ color: 'var(--muted)', padding: '24px', textAlign: 'center' }}>Алертів немає</p>
  );

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Час', 'Вузол', 'Правило', 'Опис', 'Статус'].map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left',
                color: 'var(--muted)', fontSize: 11,
                textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 500,
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={a.id} style={{
              borderBottom: '1px solid var(--border)',
              background: i % 2 === 0 ? 'transparent' : '#ffffff04',
            }}>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' }}>{fmt(a.ts)}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.node_id}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>{a.rule_triggered}</td>
              <td style={{ padding: '8px 12px', fontSize: 12, color: 'var(--muted)', maxWidth: 300 }}>{a.description}</td>
              <td style={{ padding: '8px 12px' }}>
                <span style={{
                  color: a.resolved ? 'var(--ok)' : 'var(--danger)',
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  textTransform: 'uppercase', fontWeight: 600,
                }}>{a.resolved ? '✓ resolved' : '● active'}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
