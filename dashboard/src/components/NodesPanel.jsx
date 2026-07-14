import Badge from './Badge';

function timeAgo(ts) {
  if (!ts) return '—';
  const sec = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (sec < 60) return `${sec}с тому`;
  if (sec < 3600) return `${Math.floor(sec / 60)}хв тому`;
  return `${Math.floor(sec / 3600)}год тому`;
}

export default function NodesPanel({ nodes }) {
  if (!nodes.length) return (
    <p style={{ color: 'var(--muted)', padding: '24px', textAlign: 'center' }}>Вузлів немає</p>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '8px 0' }}>
      {nodes.map(n => (
        <div key={n.node_id} style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 6,
        }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{n.hostname || n.node_id}</span>
            <span style={{ color: 'var(--muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              {n.ip_address || '—'} · last seen {timeAgo(n.last_seen)}
            </span>
          </div>
          <Badge text={n.status} />
        </div>
      ))}
    </div>
  );
}
