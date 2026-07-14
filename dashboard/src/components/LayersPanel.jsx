export default function LayersPanel({ layers, threats }) {
  if (!layers) return null;

  const total = (layers.operational || 0) + (layers.analytical || 0) + (layers.archived || 0);

  const threatColors = {
    lateral_movement: '#f85149',
    reconnaissance:   '#e3b341',
    exfiltration:     '#c084fc',
    noise:            '#3fb950',
  };

  const layerData = [
    { label: 'Operational', value: layers.operational, color: '#58a6ff', desc: 'активний моніторинг' },
    { label: 'Analytical',  value: layers.analytical,  color: '#e3b341', desc: 'підтверджені інциденти' },
    { label: 'Archive',     value: layers.archived,    color: '#3fb950', desc: 'архів' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, padding: 20 }}>
      <div>
        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
          Шари зберігання
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {layerData.map(l => {
            const pct = total > 0 ? Math.round((l.value / total) * 100) : 0;
            return (
              <div key={l.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, color: l.color, fontFamily: 'var(--font-mono)' }}>{l.label}</span>
                  <span style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                    {l.value?.toLocaleString()} ({pct}%)
                  </span>
                </div>
                <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: l.color, borderRadius: 3, transition: 'width 0.5s' }} />
                </div>
                <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>{l.desc}</div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 12, fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
          avg effectiveness: <span style={{ color: (layers.avg_effectiveness || 0) > 0.3 ? 'var(--warn)' : 'var(--muted)' }}>
            {(((layers.avg_effectiveness || 0)) * 100).toFixed(1)}%
          </span>
        </div>
      </div>

      <div>
        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
          Класи загроз
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {threats && Object.entries(threats)
            .sort(([,a],[,b]) => b - a)
            .map(([cls, cnt]) => {
              const color = threatColors[cls] || 'var(--muted)';
              const totalThreats = Object.values(threats).reduce((a,b) => a+b, 0);
              const pct = totalThreats > 0 ? Math.round((cnt / totalThreats) * 100) : 0;
              return (
                <div key={cls}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, color, fontFamily: 'var(--font-mono)' }}>{cls}</span>
                    <span style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                      {cnt?.toLocaleString()} ({pct}%)
                    </span>
                  </div>
                  <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3 }} />
                  </div>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
}
