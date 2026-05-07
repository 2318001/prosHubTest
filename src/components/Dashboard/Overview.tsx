// FILE: src/components/Dashboard/Overview.tsx — Dashboard home view. Responsive for all screen sizes.

import React from 'react';
import { Plus, MapPin, Clock, ArrowRightLeft, Zap, Briefcase, ShieldCheck, CheckCircle, XCircle } from 'lucide-react';
import { motion } from 'motion/react';

interface OverviewProps {
  user: any;
  pendingJobs: any[];
  jobs: any[];
  setView: (view: any) => void;
  onPostJob: () => void;
  setSelectedJob: (job: any) => void;
  onCancelJob?: (id: string) => void;
}

export default function Overview({ user, pendingJobs, jobs, setView, onPostJob, setSelectedJob, onCancelJob }: OverviewProps) {
  const activeJobs = jobs.filter(j => j.status !== 'finalized' && j.status !== 'cancelled');

  return (
    <div className="space-y-8 sm:space-y-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1 flex-wrap">
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Hello, {user?.name?.split(' ')[0]}!</h1>
            {user?.is_verified >= 100 && (
              <div className="text-blue-primary" title="Identity Verified">
                <ShieldCheck size={22} fill="currentColor" fillOpacity={0.1} />
              </div>
            )}
          </div>
          <p className="text-muted font-medium text-sm sm:text-base">
            {user?.role === 'pro' ? 'Manage your skills and earn money.' : 'Find the perfect specialist for your project.'}
          </p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <button
            onClick={onPostJob}
            className={`${user?.role === 'pro' ? 'btn-pro' : 'btn-primary'} flex items-center gap-2 flex-1 sm:flex-none justify-center`}
          >
            <Plus size={18} /> Post New Job
          </button>
          {user?.role === 'pro' && user?.is_verified < 100 && (
            <div className="bg-gold/10 text-gold px-3 py-2 rounded-xl font-bold text-[10px] flex items-center gap-1 border border-gold/20 whitespace-nowrap">
              <Zap size={12} /> VERIFY
            </div>
          )}
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        {[
          { label: 'Total Jobs', val: jobs.length, color: 'bg-blue-light text-blue-primary' },
          { label: 'Active', val: activeJobs.length, color: 'bg-gold/10 text-gold' },
          { label: 'Completed', val: jobs.filter(j => j.status === 'finalized').length, color: 'bg-green-light text-green-primary' },
          { label: user?.role === 'pro' ? 'Available Jobs' : 'Pending', val: user?.role === 'pro' ? pendingJobs.length : jobs.filter(j => j.status === 'pending').length, color: 'bg-paper text-muted border border-border' },
        ].map(s => (
          <div key={s.label} className={`${s.color} p-4 rounded-2xl`}>
            <div className="text-2xl sm:text-3xl font-black">{s.val}</div>
            <div className="text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">{s.label}</div>
          </div>
        ))}
      </div>

      {/* PRO: Live Feed */}
      {user?.role === 'pro' && (
        <section>
          <div className="flex items-center justify-between mb-4 sm:mb-6">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 sm:w-10 sm:h-10 bg-blue-light text-blue-primary rounded-xl flex items-center justify-center">
                <Zap size={18} className="animate-pulse" />
              </div>
              <h2 className="text-lg sm:text-xl font-black uppercase tracking-widest text-ink">Live Feed</h2>
            </div>
            <div className="flex items-center gap-2 text-green-primary font-black text-[10px] uppercase tracking-[0.15em] bg-green-light px-3 py-1.5 rounded-full border border-green-primary/20">
              <span className="w-2 h-2 bg-green-primary rounded-full animate-pulse" /> Live
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
            {pendingJobs.length === 0 ? (
              <div className="col-span-2 p-12 sm:p-16 border-2 border-dashed border-blue-primary/20 rounded-[32px] sm:rounded-[40px] text-center bg-white/50">
                <div className="text-4xl sm:text-5xl mb-4">📡</div>
                <div className="font-black text-xl sm:text-2xl mb-2">Scanning for requests...</div>
                <p className="text-muted font-bold max-w-sm mx-auto text-sm">We'll notify you when a client needs your skills.</p>
              </div>
            ) : (
              pendingJobs.map(job => (
                <motion.div
                  key={job.id}
                  className="card-brutal p-5 sm:p-8 group relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 w-20 h-20 bg-blue-primary/5 rounded-full -mr-10 -mt-10 group-hover:scale-150 transition-transform duration-500" />
                  <div className="flex justify-between items-start mb-4 relative z-10">
                    <div className="flex-1 min-w-0 pr-3">
                      <div className="inline-flex items-center gap-1.5 bg-blue-light text-blue-primary px-2.5 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest mb-2">
                        <Clock size={11} /> New Request
                      </div>
                      <h3 className="text-lg sm:text-xl font-black group-hover:text-blue-primary transition-colors truncate">{job.title}</h3>
                      <div className="flex items-center gap-3 text-xs text-muted font-bold mt-1">
                        <div className="flex items-center gap-1 truncate"><MapPin size={12} className="text-blue-primary shrink-0" /> {job.location}</div>
                      </div>
                    </div>
                    <div className="text-xl sm:text-2xl font-black text-blue-primary shrink-0">£{job.final_price || job.initial_price}</div>
                  </div>
                  <div className="flex gap-2 sm:gap-3 relative z-10">
                    <button onClick={() => setSelectedJob(job)} className="flex-1 btn-secondary py-3 flex items-center justify-center gap-1.5 text-sm">
                      <ArrowRightLeft size={16} /> Negotiate
                    </button>
                    <button onClick={() => setSelectedJob(job)} className="flex-1 btn-primary py-3 flex items-center justify-center gap-1.5 text-sm">
                      <CheckCircle size={16} /> Accept
                    </button>
                  </div>
                  {/* Pro can decline/cancel a matching job they've been assigned */}
                  {onCancelJob && job.status === 'matching' && job.pro_id === user?.id && (
                    <button
                      onClick={() => { if (window.confirm('Decline this job request?')) onCancelJob(job.id); }}
                      className="mt-2 w-full flex items-center justify-center gap-1.5 py-2 rounded-xl border border-red-200 text-red-400 text-xs font-bold hover:bg-red-50 transition-all"
                    >
                      <XCircle size={13} /> Decline Request
                    </button>
                  )}
                </motion.div>
              ))
            )}
          </div>
        </section>
      )}

      {/* Active Jobs */}
      <section>
        <div className="flex items-center justify-between mb-4 sm:mb-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 sm:w-10 sm:h-10 bg-gold/10 text-gold rounded-xl flex items-center justify-center">
              <Briefcase size={18} />
            </div>
            <h2 className="text-lg sm:text-xl font-black uppercase tracking-widest text-ink">Your Active Hub</h2>
          </div>
          {jobs.length > 0 && (
            <button onClick={() => setView('jobs')} className="text-xs font-bold text-blue-primary hover:underline">
              View All →
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 gap-4">
          {jobs.length === 0 ? (
            <div className="p-12 sm:p-16 border-2 border-dashed border-blue-primary/20 rounded-[32px] sm:rounded-[40px] text-center text-muted font-black bg-white/50">
              <div className="text-4xl mb-4">💼</div>
              <div className="text-base sm:text-lg">No active jobs yet.</div>
              <button onClick={onPostJob} className="mt-4 btn-primary text-sm">Post Your First Job</button>
            </div>
          ) : (
            activeJobs.slice(0, 5).map(job => (
              <motion.div
                key={job.id}
                onClick={() => setSelectedJob(job)}
                className="bg-white border border-blue-primary/20 p-5 sm:p-8 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between hover:border-blue-primary hover:shadow-[0_4px_20px_#2563eb20] transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-4 sm:gap-6">
                  <div className={`w-12 h-12 sm:w-16 sm:h-16 rounded-xl sm:rounded-2xl flex items-center justify-center text-2xl border border-blue-primary/20 shrink-0 ${job.status === 'finalized' ? 'bg-green-light text-green-primary' : 'bg-blue-light text-blue-primary'}`}>
                    {job.status === 'finalized' ? '✓' : '⚡'}
                  </div>
                  <div className="min-w-0">
                    <h3 className="font-black text-lg sm:text-xl group-hover:text-blue-primary transition-colors truncate">{job.title}</h3>
                    <div className="flex flex-wrap items-center gap-2 sm:gap-4 mt-1">
                      <div className={`px-2.5 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest border ${job.status === 'finalized' ? 'bg-green-light text-green-primary border-green-primary/20' : 'bg-blue-light text-blue-primary border-blue-primary/20'}`}>
                        {(job.status ?? 'pending').replace('_', ' ')}
                      </div>
                      <div className="text-sm font-black text-blue-primary">£{job.final_price || job.initial_price}</div>
                    </div>
                  </div>
                </div>
                <div className="mt-4 sm:mt-0 flex items-center gap-3 sm:gap-4">
                  <div className="hidden sm:flex flex-col items-end gap-1">
                    <div className="text-[10px] font-black uppercase tracking-widest text-muted">Progress</div>
                    <div className="w-28 h-2 bg-paper rounded-full overflow-hidden border border-border">
                      <div className={`h-full transition-all duration-1000 ${job.status === 'finalized' ? 'w-full bg-green-primary' : job.status === 'accepted' ? 'w-3/4 bg-blue-primary' : 'w-1/4 bg-gold'}`} />
                    </div>
                  </div>
                  <div className="btn-secondary p-3 rounded-2xl">
                    <ArrowRightLeft size={20} />
                  </div>
                </div>
              </motion.div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
