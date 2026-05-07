import React, { useState } from 'react';
import { MapPin, Clock, ArrowRightLeft, CheckCircle, Search, XCircle, RefreshCw } from 'lucide-react';
import { motion } from 'motion/react';

interface JobsProps {
  user: any;
  jobs: any[];
  setSelectedJob: (job: any) => void;
  onCancelJob?: (id: string) => void;
  onRaiseDispute?: (job: any) => void;
  onHireAgain?: (job: any) => void;
}

const STATUS_COLORS: Record<string, string> = {
  finalized:   'bg-green-light text-green-primary border-green-primary/20',
  accepted:    'bg-blue-light text-blue-primary border-blue-primary/20',
  matching:    'bg-gold/10 text-gold border-gold/20',
  pending:     'bg-paper text-muted border-border',
  negotiating: 'bg-purple-50 text-purple-600 border-purple-200',
  cancelled:   'bg-red-50 text-red-400 border-red-200',
  disputed:    'bg-amber-50 text-amber-600 border-amber-300',
  pro_done:    'bg-purple-50 text-purple-600 border-purple-200',
};

export default function Jobs({ user, jobs, setSelectedJob, onCancelJob, onHireAgain }: JobsProps) {
  const [filter, setFilter] = useState<'all' | 'active' | 'finalized'>('all');
  const [search, setSearch] = useState('');

  const filtered = jobs
    .filter(j => {
      if (filter === 'active') return !['finalized','cancelled'].includes(j.status);
      if (filter === 'finalized') return j.status === 'finalized';
      return true;
    })
    .filter(j => !search || j.title.toLowerCase().includes(search.toLowerCase()) || j.location?.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6 sm:space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">My Jobs</h1>
          <p className="text-muted text-sm font-medium mt-1">{jobs.length} total job{jobs.length !== 1 ? 's' : ''}</p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          {(['all', 'active', 'finalized'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`flex-1 sm:flex-none px-3 py-2 rounded-xl text-xs font-bold uppercase tracking-widest border-2 transition-all ${filter === f ? 'bg-blue-primary text-white border-blue-primary' : 'bg-white text-muted border-border hover:border-blue-primary'}`}>
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="relative">
        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted" />
        <input type="text" placeholder="Search jobs..." className="input-brutal pl-10 !py-3" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:gap-6">
        {filtered.length === 0 ? (
          <div className="p-16 sm:p-20 border-2 border-dashed border-blue-primary/20 rounded-[32px] sm:rounded-[40px] text-center bg-white/50">
            <div className="text-4xl mb-4">📂</div>
            <div className="font-bold text-lg sm:text-xl mb-2">No jobs found</div>
            <p className="text-muted font-medium text-sm">{search ? 'Try a different search term.' : "You haven't posted or accepted any jobs yet."}</p>
          </div>
        ) : filtered.map(job => {
          const isClient = job.client_id === user?.id;
          const isPro = job.pro_id === user?.id;
          const isAdmin = user?.is_admin === 1;
          const statusColor = STATUS_COLORS[job.status] || STATUS_COLORS.pending;
          const canCancel = onCancelJob && !isAdmin && (
            (isClient && ['pending', 'matching', 'negotiating'].includes(job.status)) ||
            (isPro && job.status === 'matching')
          );
          const canHireAgain = onHireAgain && isClient && job.status === 'finalized' && job.pro_id;

          return (
            <motion.div layout key={job.id} className="card-brutal p-5 sm:p-8 hover:border-blue-primary group">
              <div className="flex flex-col sm:flex-row justify-between items-start gap-4 sm:gap-6">
                <div className="flex-1 min-w-0 cursor-pointer" onClick={() => setSelectedJob(job)}>
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-widest border ${statusColor}`}>{(job.status ?? 'pending').replace('_', ' ')}</span>
                    {!isAdmin && <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-widest border ${isClient ? 'border-blue-primary text-blue-primary' : 'border-gold text-gold'}`}>{isClient ? 'Hiring' : 'Working'}</span>}
                    {isAdmin && <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-widest border border-blue-primary/40 text-blue-primary">Admin</span>}
                  </div>
                  <h2 className="text-xl sm:text-2xl font-bold mb-2 group-hover:text-blue-primary transition-colors truncate">{job.title}</h2>
                  <p className="text-muted font-medium mb-4 text-sm line-clamp-2">{job.description}</p>
                  <div className="flex flex-wrap gap-3 sm:gap-6 text-xs font-bold text-muted">
                    {job.location && <div className="flex items-center gap-1.5"><MapPin size={14} /> {job.location}</div>}
                    <div className="flex items-center gap-1.5"><Clock size={14} /> {new Date(job.created_at).toLocaleDateString()}</div>
                    <div className="flex items-center gap-1.5 text-blue-primary font-black"><ArrowRightLeft size={14} /> £{job.final_price || job.initial_price || job.price}</div>
                  </div>
                  {isAdmin && <div className="mt-3 text-xs font-bold text-muted flex flex-wrap gap-3"><span>Client: {job.client_name || 'N/A'}</span><span>Pro: {job.pro_name || 'N/A'}</span></div>}
                </div>
                <div className="w-full sm:w-auto flex flex-row sm:flex-col gap-3">
                  <button onClick={() => setSelectedJob(job)} className="btn-primary flex-1 sm:flex-none sm:w-36 py-3 text-sm">View Details</button>
                  {canCancel && (
                    <button onClick={() => { if (window.confirm('Cancel this job request?')) onCancelJob!(job.id); }}
                      className="flex items-center justify-center gap-1.5 px-3 py-3 border-2 border-red-300 text-red-400 rounded-2xl font-bold text-xs hover:bg-red-50 transition-all flex-1 sm:flex-none sm:w-36 whitespace-nowrap">
                      <XCircle size={14} /> Cancel
                    </button>
                  )}
                  {canHireAgain && (
                    <button
                      onClick={() => onHireAgain!(job)}
                      className="flex items-center justify-center gap-1.5 px-3 py-3 border-2 border-green-primary/40 text-green-primary rounded-2xl font-bold text-xs hover:bg-green-light transition-all flex-1 sm:flex-none sm:w-36 whitespace-nowrap"
                      title="Send a new hire request to the same pro"
                    >
                      <RefreshCw size={14} /> Hire Again
                    </button>
                  )}
                  {job.status === 'finalized' && !canHireAgain && (
                    <div className="flex items-center justify-center gap-1.5 text-green-primary font-bold text-xs uppercase tracking-widest">
                      <CheckCircle size={13} /> Done
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
