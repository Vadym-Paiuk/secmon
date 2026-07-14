import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import StatCard from './components/StatCard';
import EventsTable from './components/EventsTable';
import AlertsTable from './components/AlertsTable';
import NodesPanel from './components/NodesPanel';
import LayersPanel from './components/LayersPanel';
import './index.css';

const API = 'http://localhost:8000';
const GRAFANA_URL = 'http://localhost:3000/d/adhfqfn/main?orgId=1&from=now-15m&to=now&timezone=browser&kiosk=tv';
const TABS = ['Події', 'Алерти', 'Вузли', 'Шари'];

function Section({ title, children }) {
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', fontSize: 13, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {title}
      </div>
      {children}
    </div>
  );
}

export default function App() {
  const [stats, setStats]   = useState(null);
  const [layers, setLayers] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [nodes, setNodes]   = useState([]);
  const [tab, setTab]       = useState('Події');
  const [lastUpdate, setLastUpdate] = useState(null);
  const [source, setSource] = useState('all');
  const [layerFilter, setLayerFilter] = useState('all');

  const fetchAll = useCallback(async () => {
    try {
      const eventsParams = new URLSearchParams({ limit: 50 });
      if (source !== 'all') eventsParams.set('source', source);
      if (layerFilter !== 'all') eventsParams.set('layer', layerFilter);

      const [s, l, e, a, n] = await Promise.all([
        axios.get(`${API}/api/stats/summary`),
        axios.get(`${API}/api/stats/layers`),
        axios.get(`${API}/api/events?${eventsParams}`),
        axios.get(`${API}/api/alerts?resolved=false`),
        axios.get(`${API}/api/nodes`),
      ]);
      setStats(s.data);
      setLayers(l.data);
      setEvents(e.data);
      setAlerts(a.data);
      setNodes(n.data);
      setLastUpdate(new Date());
    } catch (err) {
      console.error('API error:', err);
    }
  }, [source, layerFilter]);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 10000);
    return () => clearInterval(id);
  }, [fetchAll]);

  const activeAlerts = stats?.unresolved_alerts ?? 0;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 24px', height: 22,
        background: 'var(--surface)', borderBottom: '1px solid var(--border)',
        position: 'sticky', top: 0, zIndex: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: 15, color: 'var(--accent)', letterSpacing: '0.04em' }}>
            ⬡ SECMON
          </span>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span style={{ color: 'var(--muted)', fontSize: 12 }}>Network Security Monitor v0.2</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {activeAlerts > 0 && (
            <span style={{
              background: '#2d1b1b', color: 'var(--danger)',
              border: '1px solid var(--danger)33', borderRadius: 4,
              padding: '2px 10px', fontSize: 12,
              fontFamily: 'var(--font-mono)', fontWeight: 600,
              animation: 'pulse 2s infinite',
            }}>● {activeAlerts} ACTIVE ALERTS</span>
          )}
          <span style={{ color: 'var(--muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
            {lastUpdate ? `оновлено ${lastUpdate.toLocaleTimeString('uk-UA')}` : 'завантаження...'}
          </span>
        </div>
      </header>

      <main style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 1 }} >

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8, marginBottom: 8 }}>
          <StatCard label="Всього подій"     value={stats?.total_events} />
          <StatCard label="Вузлів"           value={stats?.total_nodes} />
          <StatCard label="Активних алертів" value={activeAlerts} color={activeAlerts > 0 ? 'var(--danger)' : 'var(--ok)'} />
          <StatCard label="Analytical шар"   value={stats?.analytical_events} color="var(--warn)" sub="підтверджених" />
          <StatCard label="Firewall"         value={stats?.events_by_source?.firewall ?? 0} color="var(--accent)" />
          <StatCard label="Snort"            value={stats?.events_by_source?.snort ?? 0} color="#c084fc" />
        </div>

        {/* Grafana */}
        <Section title="Активність мережі — Grafana">
          <iframe src={GRAFANA_URL} title="Grafana"
            style={{ width: '100%', height: 430, border: 'none', display: 'block', overflow: 'hidden' }} />
        </Section>

        {/* Tabs */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)' }}>
            {TABS.map(t => (
              <button key={t} onClick={() => setTab(t)} style={{
                padding: '10px 20px', background: 'none', border: 'none',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
                color: tab === t ? 'var(--accent)' : 'var(--muted)',
                cursor: 'pointer', fontSize: 13, fontWeight: 500,
                fontFamily: 'var(--font-ui)', transition: 'color 0.15s', marginBottom: -1,
              }}>{t}</button>
            ))}

            {tab === 'Події' && (
              <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, paddingRight: 8 }}>
                {['all','firewall','snort','av'].map(s => (
                  <button key={s} onClick={() => setSource(s)} style={{
                    padding: '4px 10px', borderRadius: 4, border: '1px solid var(--border)',
                    background: source === s ? 'var(--border)' : 'transparent',
                    color: source === s ? 'var(--text)' : 'var(--muted)',
                    cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                  }}>{s}</button>
                ))}
                <span style={{ color: 'var(--border)' }}>|</span>
                {['all','operational','analytical'].map(l => (
                  <button key={l} onClick={() => setLayerFilter(l)} style={{
                    padding: '4px 10px', borderRadius: 4, border: '1px solid var(--border)',
                    background: layerFilter === l ? 'var(--border)' : 'transparent',
                    color: layerFilter === l ? 'var(--warn)' : 'var(--muted)',
                    cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                  }}>{l}</button>
                ))}
              </div>
            )}
          </div>

          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderTop: 'none', borderRadius: '0 0 8px 8px', minHeight: 200,
          }}>
            {tab === 'Події'  && <EventsTable events={events} />}
            {tab === 'Алерти' && <AlertsTable alerts={alerts} />}
            {tab === 'Вузли'  && <NodesPanel nodes={nodes} />}
            {tab === 'Шари'   && <LayersPanel layers={layers} threats={stats?.events_by_threat} />}
          </div>
        </div>
      </main>

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
      `}</style>
    </div>
  );
}
