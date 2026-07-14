import Badge from './Badge';

function fmt(ts) {
  return new Date(ts).toLocaleTimeString('uk-UA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function EventsTable({ events }) {
  if (!events.length) return (
    <p style={{ color: 'var(--muted)', padding: '24px', textAlign: 'center' }}>
      Подій поки немає
    </p>
  );

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Час', 'Вузол', 'Джерело', 'Дія', 'Src IP', 'Dst IP', 'Порт', 'Severity'].map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left',
                color: 'var(--muted)', fontSize: 11,
                textTransform: 'uppercase', letterSpacing: '0.08em',
                fontWeight: 500,
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={e.id} style={{
              borderBottom: '1px solid var(--border)',
              background: i % 2 === 0 ? 'transparent' : '#ffffff04',
              transition: 'background 0.15s',
            }}
              onMouseEnter={ev => ev.currentTarget.style.background = '#ffffff08'}
              onMouseLeave={ev => ev.currentTarget.style.background = i % 2 === 0 ? 'transparent' : '#ffffff04'}
            >
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' }}>{fmt(e.ts)}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.node_id}</td>
              <td style={{ padding: '8px 12px' }}><Badge text={e.source} /></td>
              <td style={{ padding: '8px 12px' }}><Badge text={e.action} /></td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.src_ip || '—'}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.dst_ip || '—'}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.port || '—'}</td>
              <td style={{ padding: '8px 12px' }}>
                <span style={{
                  color: e.severity >= 4 ? 'var(--danger)' : e.severity >= 3 ? 'var(--warn)' : 'var(--ok)',
                  fontFamily: 'var(--font-mono)', fontWeight: 600,
                }}>{e.severity}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
