// FILE: src/components/Dashboard/AdminDashboard.tsx — Admin verification + overview dashboard
// FIXES:
//   - Disputes tab added to tabs array (was missing — tab rendered but never reachable)
//   - ProVerificationCard no longer references `tab` from outer scope (was ReferenceError)
//   - Admin can view docs uploaded during verification (is_verification_doc=true shown first with badge)
//   - Action error cleared on retry

import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldX, Users, Briefcase, FileText, Download, AlertTriangle, CheckCircle, Clock, Search, Eye, Scale } from 'lucide-react';

const authHeader = (token: string) => ({ Authorization: `Bearer ${token}` });

interface AdminDashboardProps {
  token: string | null;
  user: any;
}

export default function AdminDashboard({ token, user }: AdminDashboardProps) {
  const [tab, setTab] = useState<'verification' | 'users' | 'jobs' | 'disputes'>('verification');
  const [pros, setPros] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [rejectId, setRejectId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDoc, setSelectedDoc] = useState<any>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [viewedDocsPros, setViewedDocsPros] = useState<Set<string>>(new Set());
  const [actionError, setActionError] = useState<string | null>(null);
  const [disputes, setDisputes] = useState<any[]>([]);

  const fetchPros = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/admin/pending-pros', { headers: authHeader(token) });
      if (r.ok) setPros(await r.json());
    } catch {}
  };
  const fetchUsers = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/admin/users', { headers: authHeader(token) });
      if (r.ok) setUsers(await r.json());
    } catch {}
  };
  const fetchDisputes = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/admin/disputes', { headers: authHeader(token) });
      if (r.ok) setDisputes(await r.json());
    } catch {}
  };
  const fetchJobs = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/admin/jobs', { headers: authHeader(token) });
      if (r.ok) setJobs(await r.json());
    } catch {}
  };

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    Promise.all([fetchPros(), fetchUsers(), fetchJobs(), fetchDisputes()]).finally(() => setLoading(false));
  }, [token]);

  const handleVerify = async (proId: string) => {
    if (!token) return;
    setActionError(null);
    setActionLoading(proId + '_verify');
    const res = await fetch(`/api/admin/verify-user/${proId}`, { method: 'POST', headers: authHeader(token) });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setActionError(data.error || 'Verification failed.');
    }
    await fetchPros();
    setActionLoading(null);
  };

  const handleReject = async (proId: string) => {
    if (!token) return;
    setActionError(null);
    setActionLoading(proId + '_reject');
    await fetch(`/api/admin/reject-user/${proId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader(token) },
      body: JSON.stringify({ reason: rejectReason }),
    });
    setRejectId(null);
    setRejectReason('');
    await fetchPros();
    setActionLoading(null);
  };

  const handleViewDoc = (doc: any, proId: string) => {
    setSelectedDoc(doc);
    setViewedDocsPros(prev => new Set(prev).add(proId));
  };

  const verificationStatus = (score: number) => {
    if (score >= 100) return { label: 'Verified',   color: 'bg-green-light text-green-primary border-green-primary/30', ring: '#10b981' };
    if (score >= 50)  return { label: 'Pending',    color: 'bg-gold/10 text-gold border-gold/30',                      ring: '#f59e0b' };
    return                   { label: 'Unverified', color: 'bg-red-50 text-red-500 border-red-300',                    ring: '#ef4444' };
  };

  const pendingPros    = pros.filter(p => p.is_verified === 50);
  const verifiedPros   = pros.filter(p => p.is_verified >= 100);

  const filteredPros = pros.filter(p =>
    !searchQuery ||
    p.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.email?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const tabs = [
    { id: 'verification', label: 'Verification', icon: ShieldCheck, badge: pendingPros.length },
    { id: 'users',        label: 'All Users',    icon: Users,        badge: users.length },
    { id: 'jobs',         label: 'All Jobs',     icon: Briefcase,    badge: jobs.length },
    { id: 'disputes',     label: 'Disputes',     icon: Scale,        badge: disputes.length },
  ] as const;

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-3">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Admin Dashboard</h1>
          <p className="text-muted font-medium text-sm mt-1">Welcome, {user?.name}. Manage verifications and platform overview.</p>
        </div>
        <div className="px-3 py-2 bg-blue-primary text-white rounded-xl font-bold text-xs flex items-center gap-1.5">
          <ShieldCheck size={13} /> Admin Access
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Pros',     val: pros.length,         color: 'bg-blue-light text-blue-primary' },
          { label: 'Pending Review', val: pendingPros.length,  color: 'bg-gold/10 text-gold' },
          { label: 'Verified',       val: verifiedPros.length, color: 'bg-green-light text-green-primary' },
          { label: 'Total Jobs',     val: jobs.length,         color: 'bg-paper text-ink' },
        ].map(s => (
          <div key={s.label} className={`${s.color} p-4 rounded-2xl border border-border text-center`}>
            <div className="text-2xl font-black">{s.val}</div>
            <div className="text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-border pb-0 overflow-x-auto">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-3 font-bold text-xs uppercase tracking-widest whitespace-nowrap border-b-2 transition-all -mb-px ${tab === t.id ? 'border-blue-primary text-blue-primary' : 'border-transparent text-muted hover:text-ink'}`}>
            <t.icon size={14} />
            {t.label}
            {t.badge > 0 && <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-black ${t.id === 'verification' && pendingPros.length > 0 ? 'bg-gold text-white' : t.id === 'disputes' ? 'bg-red-500 text-white' : 'bg-blue-primary text-white'}`}>{t.badge}</span>}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="p-20 text-center text-muted font-bold">Loading...</div>
      ) : (
        <>
          {/* ── VERIFICATION TAB ── */}
          {tab === 'verification' && (
            <div className="space-y-6">
              <div className="relative">
                <Search size={15} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted" />
                <input type="text" placeholder="Search pro by name or email..." className="input-brutal pl-10 !py-3 text-sm" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>

              {actionError && (
                <div className="flex items-center gap-3 p-4 bg-red-50 border border-red-200 rounded-2xl text-red-600">
                  <AlertTriangle size={16} className="shrink-0" />
                  <span className="text-sm font-bold">{actionError}</span>
                  <button onClick={() => setActionError(null)} className="ml-auto text-red-400 hover:text-red-600 font-bold text-lg leading-none">✕</button>
                </div>
              )}

              {/* Pending section */}
              {pendingPros.length > 0 && (
                <div className="space-y-3">
                  <h2 className="text-xs font-black uppercase tracking-widest text-gold flex items-center gap-2">
                    <Clock size={13} /> Pending Review ({pendingPros.filter(p => !searchQuery || p.name?.toLowerCase().includes(searchQuery.toLowerCase()) || p.email?.toLowerCase().includes(searchQuery.toLowerCase())).length})
                  </h2>
                  {pendingPros.filter(p => !searchQuery || p.name?.toLowerCase().includes(searchQuery.toLowerCase()) || p.email?.toLowerCase().includes(searchQuery.toLowerCase())).map(pro => (
                    <React.Fragment key={pro.id}>
                    <ProVerificationCard
                      pro={pro} onVerify={handleVerify} onReject={id => setRejectId(id)}
                      actionLoading={actionLoading} onViewDoc={(doc) => handleViewDoc(doc, pro.id)}
                      hasViewedDoc={viewedDocsPros.has(pro.id)}
                    />
                    </React.Fragment>
                  ))}
                </div>
              )}

              {/* All pros */}
              <div className="space-y-3">
                <h2 className="text-xs font-black uppercase tracking-widest text-muted flex items-center gap-2">
                  <Users size={13} /> All Pros ({filteredPros.filter(p => p.is_verified !== 50).length})
                </h2>
                {filteredPros.filter(p => p.is_verified !== 50).length === 0 ? (
                  <div className="p-12 text-center text-muted font-bold border-2 border-dashed border-border rounded-2xl">No pros found</div>
                ) : filteredPros.filter(p => p.is_verified !== 50).map(pro => (
                  <React.Fragment key={pro.id}>
                  <ProVerificationCard
                    pro={pro} onVerify={handleVerify} onReject={id => setRejectId(id)}
                    actionLoading={actionLoading} onViewDoc={(doc) => handleViewDoc(doc, pro.id)}
                    hasViewedDoc={viewedDocsPros.has(pro.id)}
                  />
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* ── USERS TAB ── */}
          {tab === 'users' && (
            <div className="space-y-3">
              <div className="relative">
                <Search size={15} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted" />
                <input type="text" placeholder="Search users..." className="input-brutal pl-10 !py-3 text-sm" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>
              <div className="overflow-x-auto rounded-2xl border-2 border-border">
                <table className="w-full text-xs font-medium">
                  <thead className="bg-paper border-b border-border">
                    <tr>
                      {['Name', 'Email', 'Role', 'Verified', 'Joined'].map(h => (
                        <th key={h} className="text-left p-3 font-black uppercase tracking-widest text-muted">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {users.filter(u => !searchQuery || u.name?.toLowerCase().includes(searchQuery.toLowerCase()) || u.email?.toLowerCase().includes(searchQuery.toLowerCase())).map(u => {
                      const vs = verificationStatus(u.is_verified);
                      return (
                        <tr key={u.id} className="border-b border-border hover:bg-paper/50 transition-colors">
                          <td className="p-3 font-bold">{u.name} {u.is_admin ? <span className="ml-1 text-blue-primary text-[9px] font-black border border-blue-primary/30 px-1.5 py-0.5 rounded-full">ADMIN</span> : ''}</td>
                          <td className="p-3 text-muted">{u.email}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded-full font-bold text-[10px] uppercase ${u.role === 'pro' ? 'bg-blue-light text-blue-primary' : 'bg-paper text-muted border border-border'}`}>{u.role}</span>
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded-full border font-bold text-[10px] ${vs.color}`}>{vs.label}</span>
                          </td>
                          <td className="p-3 text-muted">{u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── JOBS TAB ── */}
          {tab === 'jobs' && (
            <div className="space-y-3">
              <div className="relative">
                <Search size={15} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted" />
                <input type="text" placeholder="Search jobs..." className="input-brutal pl-10 !py-3 text-sm" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>
              <div className="overflow-x-auto rounded-2xl border-2 border-border">
                <table className="w-full text-xs font-medium">
                  <thead className="bg-paper border-b border-border">
                    <tr>
                      {['Title', 'Client', 'Pro', 'Status', 'Price', 'Date'].map(h => (
                        <th key={h} className="text-left p-3 font-black uppercase tracking-widest text-muted">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.filter(j => !searchQuery || j.title?.toLowerCase().includes(searchQuery.toLowerCase()) || j.client_name?.toLowerCase().includes(searchQuery.toLowerCase()) || j.pro_name?.toLowerCase().includes(searchQuery.toLowerCase())).map(j => (
                      <tr key={j.id} className="border-b border-border hover:bg-paper/50 transition-colors">
                        <td className="p-3 font-bold max-w-[200px] truncate">{j.title}</td>
                        <td className="p-3 text-muted">{j.client_name || '—'}</td>
                        <td className="p-3 text-muted">{j.pro_name || '—'}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded-full border font-bold text-[10px] uppercase ${j.status === 'finalized' ? 'bg-green-light text-green-primary border-green-primary/30' : j.status === 'cancelled' ? 'bg-red-50 text-red-400 border-red-200' : 'bg-blue-light text-blue-primary border-blue-primary/20'}`}>{j.status}</span>
                        </td>
                        <td className="p-3 font-bold text-blue-primary">£{j.final_price || j.initial_price || j.price || 0}</td>
                        <td className="p-3 text-muted">{j.created_at ? new Date(j.created_at).toLocaleDateString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── DISPUTES TAB ── */}
          {tab === 'disputes' && (
            <div className="space-y-4">
              {disputes.length === 0 ? (
                <div className="p-12 text-center text-muted font-medium border-2 border-dashed border-border rounded-2xl">
                  No open disputes
                </div>
              ) : disputes.map((job: any) => (
                <div key={job.id} className="bg-white border-2 border-amber-300 rounded-2xl p-5 space-y-3">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <AlertTriangle size={16} className="text-amber-500" />
                        <h3 className="font-bold text-base">{job.title}</h3>
                      </div>
                      <p className="text-xs text-muted mt-1">Client: {job.client_name} · Pro: {job.pro_name || 'Unassigned'}</p>
                    </div>
                    <span className="text-xs bg-amber-100 text-amber-700 font-bold px-3 py-1 rounded-full shrink-0">Disputed</span>
                  </div>
                  <div className="bg-amber-50 rounded-xl p-3">
                    <p className="text-xs font-bold text-amber-700 uppercase tracking-wider mb-1">Dispute reason</p>
                    <p className="text-sm text-amber-800">{job.dispute_reason}</p>
                  </div>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <input
                      className="flex-1 border border-border rounded-xl px-3 py-2 text-sm"
                      placeholder="Resolution notes (required)..."
                      id={`res-${job.id}`}
                    />
                    <select id={`out-${job.id}`} className="border border-border rounded-xl px-3 py-2 text-sm">
                      <option value="cancelled">Cancel job</option>
                      <option value="favour_client">Favour client</option>
                      <option value="favour_pro">Favour pro</option>
                    </select>
                    <button
                      onClick={async () => {
                        const resEl = document.getElementById(`res-${job.id}`) as HTMLInputElement;
                        const outEl = document.getElementById(`out-${job.id}`) as HTMLSelectElement;
                        if (!resEl.value.trim()) return;
                        const r = await fetch(`/api/jobs/${job.id}/resolve-dispute`, {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json', ...authHeader(token || '') },
                          body: JSON.stringify({ resolution: resEl.value, outcome: outEl.value }),
                        });
                        if (r.ok) fetchDisputes();
                      }}
                      className="px-4 py-2 bg-blue-primary text-white rounded-xl text-sm font-bold hover:bg-blue-dark transition-colors whitespace-nowrap"
                    >
                      Resolve
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* Reject Reason Modal */}
      {rejectId && (
        <div className="fixed inset-0 z-[300] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-ink/70 backdrop-blur-sm" onClick={() => setRejectId(null)} />
          <div className="relative bg-white rounded-[28px] p-8 max-w-sm w-full shadow-2xl border-2 border-red-400 space-y-4">
            <div className="flex items-center gap-3 text-red-500">
              <AlertTriangle size={22} />
              <h3 className="font-black text-lg">Reject Verification</h3>
            </div>
            <p className="text-sm text-muted font-medium">Provide a reason so the pro can fix their documents.</p>
            <textarea className="input-brutal h-24 resize-none text-sm" placeholder="e.g. ID photo is blurry, please re-upload..." value={rejectReason} onChange={e => setRejectReason(e.target.value)} />
            <div className="flex gap-3">
              <button onClick={() => handleReject(rejectId)} className="flex-1 py-3 bg-red-500 text-white rounded-2xl font-bold text-sm hover:bg-red-600 transition-all">
                Send Rejection
              </button>
              <button onClick={() => setRejectId(null)} className="flex-1 py-3 border-2 border-border rounded-2xl font-bold text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Document Preview Modal */}
      {selectedDoc && (
        <div className="fixed inset-0 z-[350] flex items-center justify-center p-4" onClick={() => setSelectedDoc(null)}>
          <div className="absolute inset-0 bg-ink/90 backdrop-blur-sm" />
          <div className="relative bg-white rounded-2xl overflow-hidden w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-border shrink-0">
              <div>
                <h4 className="font-bold">{selectedDoc.title}</h4>
                {selectedDoc.is_verification_doc && (
                  <span className="text-[9px] font-black text-blue-primary uppercase tracking-widest">Verification Document</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <a href={selectedDoc.file_url} target="_blank" rel="noreferrer" download className="flex items-center gap-1 text-xs font-bold text-blue-primary px-3 py-2 bg-blue-light rounded-xl">
                  <Download size={13} /> Download
                </a>
                <button onClick={() => setSelectedDoc(null)} className="p-2 hover:bg-paper rounded-lg">✕</button>
              </div>
            </div>
            <div className="flex-1 overflow-auto flex items-center justify-center bg-paper/50 p-4" style={{ minHeight: '300px' }}>
              {selectedDoc.file_url?.match(/\.(jpg|jpeg|png|gif|webp)/i) ? (
                <img src={selectedDoc.file_url} alt={selectedDoc.title} className="max-w-full max-h-[60vh] object-contain rounded-xl shadow-lg" />
              ) : selectedDoc.file_url?.match(/\.pdf$/i) ? (
                <iframe src={selectedDoc.file_url} className="w-full rounded-xl" style={{ height: '60vh', minHeight: '400px', border: 'none' }} title={selectedDoc.title} />
              ) : (
                <div className="flex flex-col items-center gap-4 py-10">
                  <FileText size={48} className="text-muted" />
                  <p className="font-bold">{selectedDoc.title}</p>
                  <a href={selectedDoc.file_url} target="_blank" rel="noreferrer" download className="btn-primary px-6 py-3 flex items-center gap-2">
                    <Download size={16} /> Download & Open
                  </a>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Pro Verification Card ──────────────────────────────────────────────────────
function ProVerificationCard({ pro, onVerify, onReject, actionLoading, onViewDoc, hasViewedDoc }: {
  pro: any;
  onVerify: (id: string) => void;
  onReject: (id: string) => void;
  actionLoading: string | null;
  onViewDoc: (doc: any) => void;
  hasViewedDoc: boolean;
}) {
  const ringColor = pro.is_verified >= 100 ? '#10b981' : pro.is_verified >= 50 ? '#f59e0b' : '#ef4444';
  const statusLabel = pro.is_verified >= 100 ? 'Verified' : pro.is_verified >= 50 ? 'Pending' : 'Unverified';
  const hasDocs = pro.documents?.length > 0;
  // Admin must view at least one document before actions are enabled (only if docs exist)
  const canAct = !hasDocs || hasViewedDoc;

  // Sort: verification docs first
  const sortedDocs = pro.documents ? [
    ...pro.documents.filter((d: any) => d.is_verification_doc),
    ...pro.documents.filter((d: any) => !d.is_verification_doc),
  ] : [];

  return (
    <div className="card-brutal p-5 sm:p-6 space-y-4">
      <div className="flex items-start gap-4">
        {/* Avatar with verification ring */}
        <div className="relative shrink-0">
          <svg className="absolute -inset-1.5 w-[calc(100%+12px)] h-[calc(100%+12px)] -rotate-90" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="44" fill="none" stroke={ringColor} strokeWidth="5"
              strokeDasharray={pro.is_verified >= 100 ? "100 0" : pro.is_verified >= 50 ? "60 40" : "15 85"} />
          </svg>
          <div className="w-14 h-14 bg-blue-light text-blue-primary rounded-full border border-blue-primary/20 flex items-center justify-center text-xl font-black overflow-hidden">
            {pro.avatar ? <img src={pro.avatar} className="w-full h-full object-cover rounded-full" alt={pro.name} /> : pro.name?.charAt(0)}
          </div>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-black text-base">{pro.name}</h3>
            <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full border ${pro.is_verified >= 100 ? 'bg-green-light text-green-primary border-green-primary/30' : pro.is_verified >= 50 ? 'bg-gold/10 text-gold border-gold/30' : 'bg-red-50 text-red-500 border-red-300'}`}>
              {statusLabel}
            </span>
          </div>
          <p className="text-xs text-muted font-medium">{pro.email}</p>
          {pro.location && <p className="text-xs text-muted font-medium">📍 {pro.location}</p>}
          {pro.skills?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {pro.skills.slice(0, 4).map((s: string) => (
                <span key={s} className="bg-paper border border-border px-2 py-0.5 rounded-md text-[9px] font-bold uppercase text-muted">{s}</span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Documents */}
      {sortedDocs.length > 0 ? (
        <div className="space-y-2">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <p className="text-[10px] font-black uppercase tracking-widest text-muted">
              Uploaded Documents ({sortedDocs.length})
            </p>
            {!hasViewedDoc && (
              <span className="text-[9px] font-bold text-amber-600 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">
                👁 View a document to enable actions
              </span>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {sortedDocs.map((doc: any) => (
              <div key={doc.id} className={`flex items-center justify-between p-3 border rounded-xl gap-2 ${doc.is_verification_doc ? 'bg-blue-light/30 border-blue-primary/30' : 'bg-paper border-border'}`}>
                <div className="flex items-center gap-2 min-w-0">
                  <FileText size={14} className={doc.is_verification_doc ? 'text-blue-primary shrink-0' : 'text-muted shrink-0'} />
                  <div className="min-w-0">
                    <span className="text-xs font-bold truncate block">{doc.title}</span>
                    {doc.is_verification_doc && (
                      <span className="text-[9px] font-bold text-blue-primary uppercase tracking-wider">Verification Doc</span>
                    )}
                  </div>
                </div>
                <button onClick={() => onViewDoc(doc)} className="flex items-center gap-1 text-[10px] font-bold text-blue-primary hover:bg-blue-light px-2 py-1 rounded-lg transition-all shrink-0">
                  <Eye size={11} /> View
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="p-3 bg-paper border border-dashed border-border rounded-xl text-center">
          <p className="text-xs text-muted font-medium">No documents uploaded yet</p>
        </div>
      )}

      {/* Action buttons — only show for non-verified pros */}
      {pro.is_verified < 100 && (
        <>
          {!canAct && (
            <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-xl">
              <Eye size={14} className="text-amber-600 shrink-0" />
              <span className="text-xs font-bold text-amber-700">Open at least one document above before verifying or rejecting.</span>
            </div>
          )}
          <div className="flex gap-3 pt-1">
            <button
              onClick={() => onVerify(pro.id)}
              disabled={!canAct || actionLoading === pro.id + '_verify'}
              className="flex-1 flex items-center justify-center gap-2 py-3 bg-green-primary text-white rounded-2xl font-bold text-sm hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {actionLoading === pro.id + '_verify' ? (
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <><CheckCircle size={16} /> Verify & Approve</>
              )}
            </button>
            <button
              onClick={() => onReject(pro.id)}
              disabled={!canAct || !!actionLoading}
              className="flex-1 flex items-center justify-center gap-2 py-3 border-2 border-red-400 text-red-500 rounded-2xl font-bold text-sm hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              <ShieldX size={16} /> Reject
            </button>
          </div>
        </>
      )}
      {pro.is_verified >= 100 && (
        <div className="flex items-center gap-2 p-3 bg-green-light border border-green-primary/30 rounded-xl">
          <CheckCircle size={16} className="text-green-primary" />
          <span className="text-xs font-bold text-green-primary">Verified — green ring active on profile</span>
        </div>
      )}
    </div>
  );
}
