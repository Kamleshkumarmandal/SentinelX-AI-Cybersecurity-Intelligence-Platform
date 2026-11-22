import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertOctagon, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, Check, CheckCircle2, ChevronDown, CircleHelp, Clock3, Command, FileSearch, Filter, Gauge, LayoutDashboard, LogOut, Plus, RefreshCw, Search, Shield, ShieldCheck, Siren, Sparkles, X } from 'lucide-react';
import { api, clearToken, getToken, login } from './api';

const navItems = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'alerts', label: 'Alert queue', icon: Siren },
  { id: 'events', label: 'Event stream', icon: Activity },
  { id: 'audit', label: 'Audit trail', icon: FileSearch },
];
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const fmt = (value) => new Intl.NumberFormat().format(value || 0);
const dateTime = (value) => value ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';

function LoginScreen({ onLogin }) {
  const [email, setEmail] = useState('admin@sentinelx.local');
  const [password, setPassword] = useState('ChangeMe123!');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { await login(email, password); await onLogin(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <main className="login-shell"><div className="login-grid" /><section className="login-card">
    <div className="brand-mark large"><ShieldCheck size={28} /></div>
    <div className="eyebrow">SECURITY OPERATIONS CENTER</div><h1>See the signal.<br /><span>Stop the threat.</span></h1>
    <p className="muted">Sign in to your SentinelX intelligence workspace.</p>
    <form onSubmit={submit} className="login-form"><label>Email address<input autoComplete="username" type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label><label>Password<input autoComplete="current-password" type="password" value={password} onChange={e => setPassword(e.target.value)} required /></label>
      {error && <div className="inline-error">{error}</div>}<button className="primary-btn full" disabled={busy}>{busy ? 'Connecting…' : 'Enter workspace'} <ArrowUpRight size={16} /></button>
    </form><div className="login-foot"><span className="live-dot" /> API-backed demo environment <span>·</span> Change seeded credentials before deployment</div>
  </section><div className="login-side-note"><Sparkles size={16} /> AI-assisted threat detection · Explainable risk scoring</div></main>;
}

function StatCard({ label, value, detail, icon: Icon, tone = 'blue', trend }) {
  return <article className="stat-card"><div className="stat-top"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={17} /></span></div><div className="stat-value">{value}</div><div className="stat-bottom"><span className="muted">{detail}</span>{trend && <span className="trend"><ArrowUpRight size={13} /> {trend}</span>}</div></article>;
}

function TrendChart({ data = [] }) {
  const max = Math.max(5, ...data.map(item => item.events || 0));
  const points = data.map((item, index) => {
    const x = data.length <= 1 ? 10 : 10 + index * (280 / (data.length - 1));
    const y = 104 - ((item.events || 0) / max) * 82;
    return `${x},${y}`;
  }).join(' ');
  const area = data.length ? `10,110 ${points} 290,110` : '';
  return <div className="chart-wrap"><svg viewBox="0 0 300 124" role="img" aria-label="Security events over the last seven days"><defs><linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#2dd4bf" stopOpacity=".25" /><stop offset="100%" stopColor="#2dd4bf" stopOpacity="0" /></linearGradient></defs>{[22, 63, 104].map(y => <line key={y} x1="8" x2="292" y1={y} y2={y} stroke="#243247" strokeDasharray="3 5" />)}{data.length > 1 && <polygon points={area} fill="url(#areaFill)" />}<polyline points={points} fill="none" stroke="#2dd4bf" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />{data.map((item, index) => { const x = data.length <= 1 ? 10 : 10 + index * (280 / (data.length - 1)); const y = 104 - ((item.events || 0) / max) * 82; return <circle key={item.date} cx={x} cy={y} r="3.5" fill="#07111f" stroke="#5eead4" strokeWidth="2" />; })}</svg><div className="chart-labels">{data.map(item => <span key={item.date}>{new Date(`${item.date}T00:00:00`).toLocaleDateString([], { weekday: 'short' })}</span>)}</div></div>;
}

function SeverityPill({ value }) { return <span className={`pill severity-${(value || 'low').toLowerCase()}`}><i />{value || 'low'}</span>; }
function StatusPill({ value }) { return <span className={`status-pill status-${(value || 'new').toLowerCase()}`}>{value || 'new'}</span>; }

function Overview({ summary, alerts, events, onNavigate, onSeed, onIngest, busy }) {
  const topAlerts = [...alerts].sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)).slice(0, 5);
  return <div className="page-stack">
    <section className="hero-panel"><div className="hero-copy"><div className="eyebrow mint">THREAT INTELLIGENCE / LIVE WORKSPACE</div><h2>Good evening, analyst.</h2><p>Your security posture at a glance. SentinelX is correlating signals and prioritizing suspicious activity.</p><div className="hero-actions"><button className="primary-btn" onClick={onSeed} disabled={busy}><Sparkles size={15} /> Load demo telemetry</button><button className="ghost-btn" onClick={onIngest} disabled={busy}><Plus size={15} /> Generate test event</button></div></div><div className="hero-art"><div className="radar-ring ring-one" /><div className="radar-ring ring-two" /><div className="radar-ring ring-three" /><div className="radar-core"><ShieldCheck size={36} /></div><span className="radar-node node-a" /><span className="radar-node node-b" /><span className="radar-node node-c" /><div className="radar-tag"><span className="live-dot" /> MONITORING</div></div></section>
    <section className="stat-grid"><StatCard label="Events analyzed" value={fmt(summary?.total_events)} detail="Collected security signals" icon={Activity} tone="blue" /><StatCard label="Open alerts" value={fmt(summary?.open_alerts)} detail="Require analyst attention" icon={Bell} tone="amber" /><StatCard label="Critical alerts" value={fmt(summary?.critical_alerts)} detail="Highest priority queue" icon={AlertOctagon} tone="red" /><StatCard label="Average risk" value={`${summary?.average_risk ?? 0}/100`} detail="Across ingested events" icon={Gauge} tone="violet" /></section>
    <section className="content-grid"><article className="panel chart-panel"><div className="panel-heading"><div><div className="eyebrow">TELEMETRY</div><h3>Event activity</h3><p>Security events received over the last 7 days</p></div><span className="soft-tag">7 day view</span></div><TrendChart data={summary?.trend || []} /><div className="chart-legend"><span><i /> Incoming events</span><b>{fmt(summary?.total_events)} total</b></div></article>
      <article className="panel"><div className="panel-heading"><div><div className="eyebrow">DETECTION ENGINE</div><h3>Risk distribution</h3><p>Current alert severity mix</p></div><Shield size={19} className="muted-icon" /></div><div className="risk-breakdown">{['critical', 'high', 'medium', 'low'].map(level => { const count = alerts.filter(a => a.severity === level && a.status !== 'resolved').length; const total = Math.max(1, alerts.filter(a => a.status !== 'resolved').length); return <div className="risk-row" key={level}><div><SeverityPill value={level} /><strong>{count}</strong></div><div className="progress-track"><span className={`progress-${level}`} style={{ width: `${Math.max(count ? 5 : 0, count / total * 100)}%` }} /></div></div>; })}</div><div className="engine-note"><div className="engine-check"><Check size={14} /></div><div><b>Detection pipeline operational</b><span>Rules + Isolation Forest scoring</span></div></div></article></section>
    <section className="panel"><div className="panel-heading"><div><div className="eyebrow">PRIORITY QUEUE</div><h3>Recent security alerts</h3><p>Investigate the highest-risk detections first</p></div><button className="text-btn" onClick={() => onNavigate('alerts')}>View all alerts <ArrowUpRight size={14} /></button></div><AlertTable alerts={topAlerts} compact onStatusChange={() => {}} /></section>
    <section className="panel"><div className="panel-heading"><div><div className="eyebrow">LATEST SIGNALS</div><h3>Event stream</h3><p>Most recently analyzed telemetry</p></div><button className="text-btn" onClick={() => onNavigate('events')}>Open stream <ArrowUpRight size={14} /></button></div><EventTable events={events.slice(0, 5)} /></section>
  </div>;
}

function AlertTable({ alerts, onStatusChange, compact = false }) {
  if (!alerts.length) return <div className="empty-state"><ShieldCheck size={24} /><b>No alerts in this view</b><span>Load synthetic telemetry to explore the detection workflow.</span></div>;
  return <div className="table-scroll"><table><thead><tr><th>DETECTION</th><th>SEVERITY</th><th>SOURCE</th><th>STATUS</th><th>CREATED</th>{!compact && <th>ACTION</th>}</tr></thead><tbody>{alerts.map(alert => <tr key={alert.id}><td><div className="cell-title">{alert.title}</div><div className="cell-sub">{alert.description}</div></td><td><SeverityPill value={alert.severity} /></td><td><div className="cell-title mono">{alert.event?.source_ip || '—'}</div><div className="cell-sub">{alert.event?.username || 'unknown'}</div></td><td><StatusPill value={alert.status} /></td><td className="nowrap">{dateTime(alert.created_at)}</td>{!compact && <td><select className="status-select" value={alert.status} onChange={e => onStatusChange(alert.id, e.target.value)} aria-label={`Update ${alert.title} status`}><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></td>}</tr>)}</tbody></table></div>;
}
function EventTable({ events }) {
  if (!events.length) return <div className="empty-state"><Activity size={24} /><b>No events yet</b><span>Load demo telemetry to populate the stream.</span></div>;
  return <div className="table-scroll"><table><thead><tr><th>EVENT</th><th>IDENTITY</th><th>ORIGIN</th><th>RISK SCORE</th><th>TIME</th></tr></thead><tbody>{events.map(event => <tr key={event.id}><td><div className="cell-title">{event.event_type.replaceAll('_', ' ')}</div><div className="cell-sub truncate">{event.details}</div></td><td><div className="cell-title">{event.username}</div><div className="cell-sub">{event.process_name}</div></td><td><div className="cell-title mono">{event.source_ip}</div><div className="cell-sub">{event.country}</div></td><td><div className="risk-score"><span className={`score-dot ${event.risk_level}`} />{Math.round(event.risk_score)}<small>/100</small></div></td><td className="nowrap">{dateTime(event.created_at)}</td></tr>)}</tbody></table></div>;
}

function AuditTable({ entries }) {
  if (!entries.length) return <div className="empty-state"><FileSearch size={24} /><b>No audit actions yet</b><span>Event ingestion and alert changes will appear here.</span></div>;
  return <div className="audit-list">{entries.map(item => <div className="audit-item" key={item.id}><div className="audit-icon"><CheckCircle2 size={16} /></div><div className="audit-main"><b>{item.action.replaceAll('.', ' · ')}</b><span>{item.actor_email} <i>→</i> {item.target}</span>{item.details && <small>{item.details}</small>}</div><time>{dateTime(item.created_at)}</time></div>)}</div>;
}

function EventsPage({ events, onIngest, busy }) {
  return <div className="page-stack"><div className="page-heading"><div><div className="eyebrow">COLLECTION / TELEMETRY</div><h2>Event stream</h2><p>Normalized security events and explainable risk assessments.</p></div><button className="primary-btn" onClick={onIngest} disabled={busy}><Plus size={15} /> Generate test event</button></div><div className="panel"><div className="panel-heading"><div><h3>Analyzed events</h3><p>{events.length} most recent records</p></div><span className="soft-tag">Synthetic demo data</span></div><EventTable events={events} /></div></div>;
}

function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState('overview');
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [audit, setAudit] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [toast, setToast] = useState('');
  const [alertSearch, setAlertSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const refresh = useCallback(async () => {
    const [me, stats, alertRows, eventRows, auditRows] = await Promise.all([
      api('/auth/me'), api('/summary'), api('/alerts'), api('/events?limit=100'), api('/audit'),
    ]);
    setUser(me); setSummary(stats); setAlerts(alertRows); setEvents(eventRows); setAudit(auditRows); setError('');
  }, []);
  useEffect(() => { if (getToken()) refresh().catch(err => { clearToken(); setError(err.message); }); }, [refresh]);

  async function notifyAction(action, success) {
    setBusy(true); setError('');
    try { await action(); await refresh(); setToast(success); window.setTimeout(() => setToast(''), 3200); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  const seedDemo = () => notifyAction(() => api('/demo/seed', { method: 'POST' }), 'Demo telemetry loaded');
  const ingestTest = () => notifyAction(() => api('/events', { method: 'POST', body: JSON.stringify({ event_type: 'login_failure', source_ip: '198.51.100.222', username: 'demo-operator', country: 'ZZ', failed_attempts: 11, bytes_out: 1200, unusual_hour: true, process_name: 'browser', details: 'Manually generated synthetic event for analyst workflow testing' }) }), 'Synthetic event analyzed');
  const changeAlertStatus = (id, status) => notifyAction(() => api(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }), 'Alert status updated');
  async function handleLogout() { clearToken(); setUser(null); setSummary(null); setAlerts([]); setEvents([]); setAudit([]); }
  const filteredAlerts = useMemo(() => alerts.filter(alert => (severityFilter === 'all' || alert.severity === severityFilter) && `${alert.title} ${alert.description} ${alert.event?.source_ip || ''}`.toLowerCase().includes(alertSearch.toLowerCase())), [alerts, severityFilter, alertSearch]);

  if (!user) return <LoginScreen onLogin={refresh} />;
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark"><ShieldCheck size={21} /></div><div><b>sentinel<span>x</span></b><small>THREAT INTELLIGENCE</small></div></div><div className="workspace-label">WORKSPACE</div><nav>{navItems.map(item => { const Icon = item.icon; return <button key={item.id} className={`nav-link ${page === item.id ? 'active' : ''}`} onClick={() => setPage(item.id)}><Icon size={17} /><span>{item.label}</span>{item.id === 'alerts' && summary?.open_alerts > 0 && <i>{summary.open_alerts}</i>}</button>; })}</nav><div className="sidebar-bottom"><div className="environment-card"><div className="env-head"><span className="live-dot" /> ENVIRONMENT</div><b>Development / Demo</b><small>Detection engine enabled</small></div><div className="profile-row"><div className="avatar">{user.email.slice(0, 1).toUpperCase()}</div><div className="profile-info"><b>{user.email}</b><small>{user.role} access</small></div><button className="icon-button" onClick={handleLogout} title="Sign out"><LogOut size={16} /></button></div></div></aside>
    <main className="main-area"><header className="topbar"><div className="breadcrumb"><span>SentinelX</span><i>/</i><b>{navItems.find(item => item.id === page)?.label || page}</b></div><div className="topbar-actions"><span className="system-status"><i className="live-dot" /> All systems normal</span><button className="icon-button" onClick={() => notifyAction(refresh, 'Workspace refreshed')} title="Refresh data"><RefreshCw size={16} /></button><div className="top-avatar">{user.email.slice(0, 1).toUpperCase()}</div></div></header>
      <div className="page-container">{error && <div className="error-banner"><AlertTriangle size={16} />{error}<button onClick={() => setError('')}><X size={15} /></button></div>}
        {page === 'overview' && <><div className="page-heading compact-heading"><div><div className="eyebrow">COMMAND CENTER</div><h2>Security overview</h2><p>Monitor, investigate, and respond to suspicious activity.</p></div><button className="icon-button bordered" onClick={() => notifyAction(refresh, 'Workspace refreshed')}><RefreshCw size={16} /></button></div><Overview summary={summary || {}} alerts={alerts} events={events} onNavigate={setPage} onSeed={seedDemo} onIngest={ingestTest} busy={busy} /></>}
        {page === 'alerts' && <div className="page-stack"><div className="page-heading"><div><div className="eyebrow">DETECTION / RESPONSE</div><h2>Alert queue</h2><p>Prioritized findings requiring review and disposition.</p></div><span className="soft-tag">{filteredAlerts.length} results</span></div><div className="filter-bar"><div className="search-box"><Search size={16} /><input value={alertSearch} onChange={e => setAlertSearch(e.target.value)} placeholder="Search detections, details, IP…" /></div><div className="select-wrap"><Filter size={15} /><select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select><ChevronDown size={14} /></div></div><div className="panel"><AlertTable alerts={filteredAlerts} onStatusChange={changeAlertStatus} /></div></div>}
        {page === 'events' && <EventsPage events={events} onIngest={ingestTest} busy={busy} />}
        {page === 'audit' && <div className="page-stack"><div className="page-heading"><div><div className="eyebrow">GOVERNANCE / ACCOUNTABILITY</div><h2>Audit trail</h2><p>Trace analyst activity and security workflow changes.</p></div><span className="soft-tag">Append-only activity log</span></div><div className="panel"><AuditTable entries={audit} /></div></div>}
      </div><footer className="footer"><span>SentinelX v0.1.0 · Portfolio MVP</span><span><CircleHelp size={13} /> Synthetic telemetry only · Not a production SIEM</span></footer></main>{toast && <div className="toast"><CheckCircle2 size={17} />{toast}</div>}{busy && <div className="busy-indicator"><RefreshCw size={13} /> Syncing</div>}</div>;
}

export default App;
