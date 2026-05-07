import React, { useState } from 'react';
import { X, Upload, AlertTriangle, MessageSquare, CheckCircle, Star, Clock, XCircle, Briefcase, Play, FileText, Send, Lock, ArrowRightLeft } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface ModalsProps {
  showPostModal: boolean; setShowPostModal: (v: boolean) => void;
  handlePostJob: (e: React.FormEvent) => void;
  postTitle: string; setPostTitle: (v: string) => void;
  postDesc: string; setPostDesc: (v: string) => void;
  postBudget: string; setPostBudget: (v: string) => void;
  postLocation: string; setPostLocation: (v: string) => void;
  postCategory: string; setPostCategory: (v: string) => void;
  postSkills: string[]; setPostSkills: React.Dispatch<React.SetStateAction<string[]>>;
  categories: any[]; postFile: File | null; setPostFile: (v: File | null) => void;
  selectedJob: any; setSelectedJob: (v: any) => void;
  messages: any[]; newMessage: string; setNewMessage: (v: string) => void;
  handleSendMessage: (e: React.FormEvent) => void;
  offers: any[];
  onAcceptJob: (id: string) => void; onConfirmMatch: (id: string) => void;
  onCompleteJob: (id: string, rating?: number, comment?: string) => void;
  onMarkDone: (id: string) => void;
  onAcceptOffer: (id: string) => void; onNegotiate: (id: string, amount: number) => void;
  onCancelJob: (id: string) => void;
  user: any; token: string | null;
  showWorkModal: boolean; setShowWorkModal: (v: boolean) => void;
  handleAddWork: (e: React.FormEvent) => void;
  workTitle: string; setWorkTitle: (v: string) => void;
  workDesc: string; setWorkDesc: (v: string) => void;
  workImage: string; setWorkImage: (v: string) => void;
  workFile: File | null; setWorkFile: (v: File | null) => void;
  showDeleteModal: boolean; setShowDeleteModal: (v: boolean) => void;
  handleDeleteAccount: () => void;
  isPublicProfile: boolean; setIsPublicProfile: (v: boolean) => void;
  isPublicDocs: boolean; setIsPublicDocs: (v: boolean) => void;
  handleToggleVisibility: (type: 'profile' | 'docs', value: boolean) => void;
  userDocuments: any[];
  handleUploadDocument: (title: string, url: string) => void;
  handleDeleteDocument: (id: string) => void;
  showDirectHireModal: boolean; setShowDirectHireModal: (v: boolean) => void;
  directHirePro: any; directHirePrice: string; setDirectHirePrice: (v: string) => void;
  directHireDesc: string; setDirectHireDesc: (v: string) => void;
  handleDirectHire: () => void;
}

export default function Modals(props: ModalsProps) {
  const {
    showPostModal, setShowPostModal, handlePostJob, postTitle, setPostTitle, postDesc, setPostDesc,
    postBudget, setPostBudget, postLocation, setPostLocation, postCategory, setPostCategory,
    postSkills, setPostSkills, categories, postFile, setPostFile,
    selectedJob, setSelectedJob, messages, newMessage, setNewMessage, handleSendMessage,
    offers, onAcceptJob, onConfirmMatch, onCompleteJob, onMarkDone, onAcceptOffer, onNegotiate, onCancelJob,
    user, showWorkModal, setShowWorkModal, handleAddWork, workTitle, setWorkTitle,
    workDesc, setWorkDesc, workImage, setWorkImage, workFile, setWorkFile,
    showDeleteModal, setShowDeleteModal, handleDeleteAccount,
    showDirectHireModal, setShowDirectHireModal, directHirePro, directHirePrice, setDirectHirePrice,
    directHireDesc, setDirectHireDesc, handleDirectHire,
  } = props;
  const [negotiateAmount, setNegotiateAmount] = useState('');
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [mobileTab, setMobileTab] = useState<'info' | 'chat'>('info');
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const chatEndRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    setMobileTab('info'); setNegotiateAmount(''); setRating(5); setComment(''); setShowCancelConfirm(false);
  }, [selectedJob?.id]);

  React.useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const canCancel = selectedJob && user && (
    (['pending', 'negotiating'].includes(selectedJob.status) && String(selectedJob.client_id) === String(user.id)) ||
    (selectedJob.status === 'matching' && (String(selectedJob.client_id) === String(user.id) || String(selectedJob.pro_id) === String(user.id)))
  );

  const isLocked = selectedJob?.status === 'finalized' || selectedJob?.locked;
  const isActiveJob = selectedJob?.status === 'accepted';
  const isClientView = user?.role === 'client';
  const isProView = user?.role === 'pro';
  const proIdMatch    = selectedJob && user && String(selectedJob.pro_id)    === String(user.id);
  const clientIdMatch = selectedJob && user && String(selectedJob.client_id) === String(user.id);
  const canMarkDone = isActiveJob && isProView && proIdMatch;
  const canComplete = selectedJob?.status === 'pro_done' && isClientView && clientIdMatch;

  // Dispute: available to either party on accepted/negotiating/pro_done jobs (not already disputed/cancelled/finalized)
  const isParticipant = selectedJob && user && (proIdMatch || clientIdMatch);
  const canDispute = isParticipant && selectedJob && !['cancelled','finalized','disputed','pending'].includes(selectedJob.status);
  const [showDisputeForm, setShowDisputeForm] = React.useState(false);
  const [disputeReason, setDisputeReason] = React.useState('');
  const [disputeLoading, setDisputeLoading] = React.useState(false);
  const token = props.token;

  const handleRaiseDispute = async () => {
    if (!token || !selectedJob || disputeReason.trim().length < 10) return;
    setDisputeLoading(true);
    try {
      const res = await fetch(`/api/jobs/${selectedJob.id}/dispute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ reason: disputeReason }),
      });
      const data = await res.json();
      if (res.ok) {
        setShowDisputeForm(false);
        setDisputeReason('');
        // Refresh job status
        const updated = await fetch(`/api/jobs/${selectedJob.id}`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (updated.ok) setSelectedJob(await updated.json());
      } else {
        alert(data.error || 'Failed to raise dispute');
      }
    } catch { alert('Network error. Please try again.'); }
    setDisputeLoading(false);
  };

  return (
    <>
      {/* ── POST JOB MODAL ── */}
      <AnimatePresence>
        {showPostModal && (
          <div className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center p-0 sm:p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setShowPostModal(false)} className="absolute inset-0 bg-ink/60 backdrop-blur-sm" />
            <motion.div
              initial={{ y: '100%', opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: '100%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="relative bg-white border-t border-t-blue-primary/30 sm:border sm:border-blue-primary/30 p-6 sm:p-8 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-2xl max-h-[92vh] overflow-y-auto"
            >
              <div className="w-12 h-1.5 bg-border rounded-full mx-auto mb-4 sm:hidden" />
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl sm:text-3xl font-bold">Post a New Job</h2>
                <button onClick={() => setShowPostModal(false)} className="p-2 hover:bg-paper rounded-xl"><X size={24} /></button>
              </div>
              <form onSubmit={handlePostJob} className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Job Title</label>
                    <input type="text" required placeholder="e.g. Fix Leaking Pipe" className="input-brutal" value={postTitle} onChange={e => setPostTitle(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Category</label>
                    <select className="input-brutal" value={postCategory} onChange={e => { setPostCategory(e.target.value); if (!postSkills.includes(e.target.value)) setPostSkills([e.target.value]); }}>
                      <option value="">Select Category</option>
                      {categories.map(cat => <option key={cat.name} value={cat.name}>{cat.name}</option>)}
                    </select>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">Description</label>
                  <textarea required minLength={10} placeholder="Describe what needs to be done (min 10 chars)..." className="input-brutal h-28 resize-none" value={postDesc} onChange={e => setPostDesc(e.target.value)} />
                  {postDesc.length > 0 && postDesc.length < 10 && (
                    <p className="text-xs text-red-500 font-bold">{10 - postDesc.length} more characters needed</p>
                  )}
                </div>
                {categories.length > 0 && (
                  <div className="space-y-2">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Required Skills (only matching pros will be notified)</label>
                    <div className="flex flex-wrap gap-2 p-3 border-2 border-border rounded-xl bg-paper">
                      {categories.map(cat => (
                        <button key={cat.name} type="button"
                          onClick={() => setPostSkills(prev => prev.includes(cat.name) ? prev.filter(s => s !== cat.name) : [...prev, cat.name])}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all border-2 ${postSkills.includes(cat.name) ? 'bg-blue-primary text-white border-blue-primary' : 'bg-white text-muted border-border hover:border-blue-primary'}`}>
                          {cat.name}
                        </button>
                      ))}
                    </div>
                    <p className="text-[10px] text-muted font-medium">Selected: {postSkills.length > 0 ? postSkills.join(', ') : 'None (will use category)'}</p>
                  </div>
                )}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Budget (£)</label>
                    <input type="number" required placeholder="50" className="input-brutal" value={postBudget} onChange={e => setPostBudget(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Location</label>
                    <input type="text" required placeholder="e.g. London or Remote" className="input-brutal" value={postLocation} onChange={e => setPostLocation(e.target.value)} />
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">Reference Photo (Optional)</label>
                  <div className="relative">
                    <input type="file" className="hidden" id="job-file" onChange={e => setPostFile(e.target.files?.[0] || null)} />
                    <label htmlFor="job-file" className="input-brutal flex items-center gap-2 cursor-pointer hover:bg-paper">
                      <Upload size={16} /><span className="truncate text-sm">{postFile ? postFile.name : 'Upload reference...'}</span>
                    </label>
                  </div>
                </div>
                <div className="flex gap-3 pt-2">
                  <button type="submit" className="flex-1 btn-primary py-4">Post Job</button>
                  <button type="button" onClick={() => setShowPostModal(false)} className="flex-1 btn-secondary py-4">Cancel</button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── DIRECT HIRE MODAL ── */}
      <AnimatePresence>
        {showDirectHireModal && directHirePro && (
          <div className="fixed inset-0 z-[200] flex items-end sm:items-center justify-center p-0 sm:p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setShowDirectHireModal(false)} className="absolute inset-0 bg-ink/60 backdrop-blur-sm" />
            <motion.div
              initial={{ y: '100%', opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: '100%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="relative bg-white border-t border-t-blue-primary/30 sm:border sm:border-blue-primary/30 p-6 sm:p-8 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-md max-h-[90vh] overflow-y-auto"
            >
              <div className="w-12 h-1.5 bg-border rounded-full mx-auto mb-4 sm:hidden" />
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl sm:text-2xl font-bold">Hire {directHirePro.name}</h2>
                  <p className="text-xs text-muted font-bold mt-1">{directHirePro.skills?.slice(0, 3).join(', ')}</p>
                </div>
                <button onClick={() => setShowDirectHireModal(false)} className="p-2 hover:bg-paper rounded-xl"><X size={22} /></button>
              </div>
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">Your Budget (£)</label>
                  <input type="number" required placeholder="e.g. 150" className="input-brutal text-lg font-black" value={directHirePrice} onChange={e => setDirectHirePrice(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">What do you need? (Optional)</label>
                  <textarea placeholder="Briefly describe the work..." className="input-brutal h-24 resize-none" value={directHireDesc} onChange={e => setDirectHireDesc(e.target.value)} />
                </div>
                <div className="p-4 bg-blue-light border-2 border-blue-primary/20 rounded-2xl">
                  <p className="text-xs font-bold text-blue-primary">✓ {directHirePro.name} will receive your request directly and can accept or negotiate.</p>
                </div>
                <div className="flex gap-3 pt-1">
                  <button onClick={handleDirectHire} disabled={!directHirePrice} className="flex-1 btn-primary py-4 flex items-center justify-center gap-2 disabled:opacity-40">
                    <Briefcase size={18} /> Send Hire Request
                  </button>
                  <button onClick={() => setShowDirectHireModal(false)} className="flex-1 btn-secondary py-4">Cancel</button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── JOB DETAIL / CHAT MODAL ── */}
      <AnimatePresence>
        {selectedJob && (
          <div className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center p-0 sm:p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedJob(null)} className="absolute inset-0 bg-ink/60 backdrop-blur-sm" />
            <motion.div
              initial={{ y: '100%', opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: '100%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="relative bg-white border-t border-t-blue-primary/30 sm:border sm:border-blue-primary/30 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-5xl h-[92vh] sm:h-[85vh] flex flex-col overflow-hidden"
            >
              <div className="w-12 h-1.5 bg-border rounded-full mx-auto mt-3 mb-1 sm:hidden shrink-0" />
              {/* Header */}
              <div className="px-4 sm:px-6 py-3 sm:py-4 border-b border-blue-primary/20 flex justify-between items-start bg-paper shrink-0">
                <div className="flex-1 min-w-0 pr-4">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-lg sm:text-2xl font-bold truncate">{selectedJob.title}</h2>
                    {isLocked && (
                      <span className="flex items-center gap-1 px-2 py-0.5 bg-red-50 border border-red-200 text-red-500 rounded-full text-[10px] font-bold">
                        <Lock size={10} /> Locked
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-xs font-bold text-muted uppercase tracking-widest mt-1">
                    <span>£{selectedJob.final_price || selectedJob.initial_price || selectedJob.price || 0}</span>
                    <span>•</span>
                    <span className="capitalize">{(selectedJob.status ?? 'pending').replace('_', ' ')}</span>
                    {selectedJob.category && <span className="text-blue-primary">• {selectedJob.category}</span>}
                  </div>
                </div>
                <button onClick={() => setSelectedJob(null)} className="p-2 hover:bg-ink hover:text-white rounded-xl transition-all shrink-0"><X size={22} /></button>
              </div>

              {/* Mobile Tabs */}
              <div className="flex sm:hidden border-b border-blue-primary/20 shrink-0">
                <button onClick={() => setMobileTab('info')} className={`flex-1 py-3 text-xs font-black uppercase tracking-widest ${mobileTab === 'info' ? 'bg-ink text-white' : 'bg-paper text-muted'}`}>Actions</button>
                <button onClick={() => setMobileTab('chat')} className={`flex-1 py-3 text-xs font-black uppercase tracking-widest ${mobileTab === 'chat' ? 'bg-ink text-white' : 'bg-paper text-muted'}`}>
                  Chat {messages.length > 0 && `(${messages.length})`}
                  {isLocked && ' 🔒'}
                </button>
              </div>

              <div className="flex-1 flex overflow-hidden">
                {/* Info Panel */}
                <div className={`${mobileTab === 'chat' ? 'hidden' : 'flex'} sm:flex flex-col w-full sm:w-1/2 border-r-0 sm:border-r border-blue-primary/20 overflow-y-auto`}>
                  <div className="p-4 sm:p-6 space-y-4">
                    <section className="space-y-3">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-muted">Job Actions</h3>

                      {canCancel && !showCancelConfirm && (
                        <button onClick={() => setShowCancelConfirm(true)} className="w-full flex items-center justify-center gap-2 py-3 border-2 border-red-400 text-red-500 rounded-2xl font-bold hover:bg-red-50 transition-all text-sm">
                          <XCircle size={16} /> Cancel Job Request
                        </button>
                      )}
                      {showCancelConfirm && (
                        <div className="p-4 bg-red-50 border-2 border-red-400 rounded-2xl space-y-3">
                          <p className="text-sm font-bold text-red-600">Are you sure you want to cancel?</p>
                          <div className="flex gap-2">
                            <button onClick={() => { onCancelJob(selectedJob.id); setShowCancelConfirm(false); }} className="flex-1 py-2 bg-red-500 text-white rounded-xl font-bold text-sm">Yes, Cancel</button>
                            <button onClick={() => setShowCancelConfirm(false)} className="flex-1 py-2 border-2 border-border rounded-xl font-bold text-sm">Keep Job</button>
                          </div>
                        </div>
                      )}

                      {/* Pro: accept or negotiate — shown when job is pending OR negotiating */}
                      {isProView && (selectedJob.status === 'pending' || selectedJob.status === 'negotiating') && (
                        <div className="space-y-3">
                          {selectedJob.status === 'pending' && (
                            <button onClick={() => onAcceptJob(selectedJob.id)} className="w-full btn-primary py-4 flex items-center justify-center gap-2">
                              <CheckCircle size={18} /> Accept Job (£{selectedJob.initial_price || 0})
                            </button>
                          )}
                          <div className="p-4 bg-blue-light border-2 border-blue-primary/20 rounded-2xl space-y-3">
                            <p className="text-xs font-bold text-blue-primary uppercase tracking-widest">
                              {selectedJob.status === 'negotiating' ? '↩ Send Counter-Offer' : 'Or Negotiate Price'}
                            </p>
                            <div className="flex gap-2">
                              <input type="number" placeholder="Your Price (£)" className="flex-1 p-3 bg-white border-2 border-blue-primary/20 rounded-xl font-bold outline-none focus:border-blue-primary" value={negotiateAmount} onChange={e => setNegotiateAmount(e.target.value)} />
                              <button onClick={() => { if (negotiateAmount) { onNegotiate(selectedJob.id, Number(negotiateAmount)); setNegotiateAmount(''); } }} className="btn-pro px-4 py-2 text-sm whitespace-nowrap">Send</button>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* NEGOTIATION HUB — Full offer history + counter for BOTH sides */}
                      {selectedJob.status === 'negotiating' && !['accepted','finalized','cancelled'].includes(selectedJob.status) && (
                        <div className="space-y-3">
                          {/* Offer thread */}
                          {offers.length > 0 && (
                            <div className="space-y-2">
                              <h4 className="text-xs font-bold uppercase tracking-widest text-muted flex items-center gap-2">
                                <ArrowRightLeft size={13} /> Negotiation History
                              </h4>
                              <div className="max-h-48 overflow-y-auto space-y-2 pr-1">
                                {offers.map((offer, idx) => {
                                  const isMine = String(offer.sender_id) === String(user?.id);
                                  const isLatest = idx === offers.length - 1;
                                  return (
                                    <div key={offer.id} className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}>
                                      <div className={`max-w-[80%] p-3 rounded-2xl border-2 ${isLatest ? 'border-blue-primary/40 shadow-[0_2px_8px_#2563eb20]' : 'border-border'} ${isMine ? 'bg-blue-primary text-white rounded-tr-none' : 'bg-white rounded-tl-none'}`}>
                                        <div className={`text-lg font-black ${isMine ? 'text-white' : 'text-blue-primary'}`}>£{offer.amount}</div>
                                        <div className={`text-[10px] font-bold mt-0.5 ${isMine ? 'text-white/70' : 'text-muted'}`}>
                                          {isMine ? 'You' : offer.sender_name || 'Other party'}
                                          {isLatest && <span className="ml-1 text-[9px] uppercase tracking-widest">(latest)</span>}
                                        </div>
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}

                          {/* Accept latest offer — shown if the latest offer is from the OTHER party */}
                          {offers.length > 0 && String(offers[offers.length - 1].sender_id) !== String(user?.id) && (
                            <button
                              onClick={() => onAcceptOffer(offers[offers.length - 1].id)}
                              className="w-full btn-primary py-3 flex items-center justify-center gap-2 !bg-green-primary !border-green-primary"
                            >
                              <CheckCircle size={16} /> Accept £{offers[offers.length - 1].amount}
                            </button>
                          )}

                          {/* Counter-offer input — BOTH client and pro can counter */}
                          {(isClientView || isProView) && (
                            <div className="p-3 bg-blue-light/50 border-2 border-blue-primary/20 rounded-2xl space-y-2">
                              <p className="text-[10px] font-bold text-blue-primary uppercase tracking-widest">Send Counter-Offer</p>
                              <div className="flex gap-2">
                                <input
                                  type="number"
                                  placeholder="Your counter price (£)"
                                  className="flex-1 p-2.5 bg-white border-2 border-blue-primary/20 rounded-xl font-bold outline-none focus:border-blue-primary text-sm"
                                  value={negotiateAmount}
                                  onChange={e => setNegotiateAmount(e.target.value)}
                                  onKeyDown={e => { if (e.key === 'Enter' && negotiateAmount) { onNegotiate(selectedJob.id, Number(negotiateAmount)); setNegotiateAmount(''); } }}
                                />
                                <button
                                  onClick={() => { if (negotiateAmount) { onNegotiate(selectedJob.id, Number(negotiateAmount)); setNegotiateAmount(''); } }}
                                  disabled={!negotiateAmount}
                                  className="btn-pro px-4 py-2 text-sm whitespace-nowrap disabled:opacity-40"
                                >
                                  Counter
                                </button>
                              </div>
                              <p className="text-[9px] text-muted">Both parties can counter until one accepts.</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Matching */}
                      {selectedJob.status === 'matching' && (
                        <div className="p-5 bg-gold/10 border-2 border-gold/20 rounded-2xl space-y-4">
                          <div className="flex items-center gap-3 text-gold"><Clock size={22} /><h4 className="font-black uppercase tracking-widest text-sm">Match Pending</h4></div>
                          <p className="text-sm font-bold text-ink/70">Both parties must confirm before work begins.</p>
                          <button onClick={() => onConfirmMatch(selectedJob.id)} className="w-full bg-gold text-white py-4 rounded-2xl font-black border border-gold/40 hover:opacity-90 transition-all">
                            Confirm Match ✓
                          </button>
                        </div>
                      )}

                      {/* Pro: mark done */}
                      {canMarkDone && (
                        <div className="p-5 bg-green-light border-2 border-green-primary/20 rounded-2xl space-y-3">
                          <div className="flex items-center gap-3 text-green-primary"><CheckCircle size={22} /><h4 className="font-black uppercase tracking-widest text-sm">Job In Progress</h4></div>
                          <p className="text-sm font-bold text-ink/70">Finished? Mark done — client will be asked to confirm.</p>
                          <button onClick={() => onMarkDone(selectedJob.id)} className="w-full btn-primary py-4 !bg-green-primary !border-green-primary flex items-center justify-center gap-2">
                            <CheckCircle size={18} /> Mark Job as Done
                          </button>
                        </div>
                      )}

                      {/* Pro: waiting for review */}
                      {isProView && selectedJob.status === 'pro_done' && (
                        <div className="p-4 bg-gold/10 border-2 border-gold/30 rounded-2xl">
                          <p className="text-sm font-bold text-gold">⏳ Waiting for client to confirm and optionally leave a review.</p>
                        </div>
                      )}

                      {/* Client: pro done — optional review */}
                      {canComplete && (
                        <div className="p-5 bg-green-light border-2 border-green-primary/20 rounded-2xl space-y-4">
                          <div className="flex items-center gap-3 text-green-primary"><CheckCircle size={22} /><h4 className="font-black uppercase tracking-widest text-sm">Pro Marked Job Done!</h4></div>
                          <p className="text-sm font-bold text-ink/70">Would you like to leave a review? Completely optional.</p>
                          <div className="space-y-3">
                            <div className="flex items-center gap-1">
                              {[1,2,3,4,5].map(s => (
                                <button key={s} type="button" onClick={() => setRating(s)} className={`p-1 transition-colors ${rating >= s ? 'text-gold' : 'text-muted'}`}>
                                  <Star size={22} fill={rating >= s ? 'currentColor' : 'none'} />
                                </button>
                              ))}
                              <span className="ml-2 text-xs text-muted font-bold">Optional</span>
                            </div>
                            <textarea
                              placeholder="Leave a comment (optional)..."
                              className="w-full p-3 bg-white border-2 border-border rounded-xl text-sm h-20 outline-none resize-none focus:border-green-primary transition-colors"
                              value={comment} onChange={e => setComment(e.target.value)}
                            />
                            <div className="grid grid-cols-2 gap-2">
                              <button onClick={() => onCompleteJob(selectedJob.id, rating, comment)} className="btn-primary py-3 !bg-green-primary !border-green-primary text-sm flex items-center justify-center gap-1.5">
                                <Star size={14} /> Confirm + Review
                              </button>
                              <button onClick={() => onCompleteJob(selectedJob.id, undefined, undefined)} className="btn-secondary py-3 text-sm flex items-center justify-center gap-1.5">
                                <CheckCircle size={14} /> Close Job Only
                              </button>
                            </div>
                            <p className="text-[10px] text-muted text-center">"Close Job Only" finalises without a review. Chat will be locked after.</p>
                          </div>
                        </div>
                      )}

                      {/* Client waiting */}
                      {isClientView && isActiveJob && clientIdMatch && (
                        <div className="p-4 bg-blue-light border-2 border-blue-primary/20 rounded-2xl">
                          <p className="text-sm font-bold text-blue-primary">⏳ Waiting for the pro to mark the job as done. You'll be notified to confirm.</p>
                        </div>
                      )}

                      {selectedJob.status === 'cancelled' && (
                        <div className="p-4 bg-red-50 border-2 border-red-300 rounded-2xl flex items-center gap-3 text-red-500">
                          <XCircle size={20} /><span className="font-black uppercase tracking-widest text-sm">Job Cancelled</span>
                        </div>
                      )}

                      {/* Dispute button — shows for accepted/negotiating/pro_done jobs */}
                      {canDispute && !showDisputeForm && selectedJob.status !== 'disputed' && (
                        <button
                          onClick={() => setShowDisputeForm(true)}
                          className="w-full flex items-center justify-center gap-2 py-3 border-2 border-amber-400 text-amber-600 rounded-2xl font-bold hover:bg-amber-50 transition-all text-sm mt-2"
                        >
                          <AlertTriangle size={16} /> Raise a Dispute
                        </button>
                      )}

                      {/* Dispute form */}
                      {showDisputeForm && (
                        <div className="p-4 bg-amber-50 border-2 border-amber-400 rounded-2xl space-y-3">
                          <p className="text-sm font-bold text-amber-700">Describe the issue. An admin will review and resolve it.</p>
                          <textarea
                            className="w-full p-3 bg-white border-2 border-amber-300 rounded-xl text-sm h-24 outline-none resize-none focus:border-amber-500 transition-colors"
                            placeholder="Explain the problem in detail (min 10 characters)..."
                            value={disputeReason}
                            onChange={e => setDisputeReason(e.target.value)}
                          />
                          <div className="flex gap-2">
                            <button
                              onClick={handleRaiseDispute}
                              disabled={disputeLoading || disputeReason.trim().length < 10}
                              className="flex-1 py-2.5 bg-amber-500 text-white rounded-xl font-bold text-sm disabled:opacity-40"
                            >
                              {disputeLoading ? 'Submitting...' : 'Submit Dispute'}
                            </button>
                            <button onClick={() => { setShowDisputeForm(false); setDisputeReason(''); }} className="flex-1 py-2.5 border-2 border-border rounded-xl font-bold text-sm">
                              Cancel
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Already disputed */}
                      {selectedJob.status === 'disputed' && (
                        <div className="p-4 bg-amber-50 border-2 border-amber-400 rounded-2xl flex items-start gap-3">
                          <AlertTriangle size={20} className="text-amber-600 shrink-0 mt-0.5" />
                          <div>
                            <p className="font-black text-amber-700 text-sm uppercase tracking-widest">Dispute Open</p>
                            <p className="text-xs text-amber-600 mt-1">An admin is reviewing this dispute. You'll be notified once it's resolved.</p>
                          </div>
                        </div>
                      )}

                      {isLocked && (
                        <div className="p-4 bg-green-light border-2 border-green-primary/20 rounded-2xl space-y-2">
                          <div className="flex items-center gap-3 text-green-primary">
                            <CheckCircle size={20} /><span className="font-black uppercase tracking-widest text-sm">Job Completed ✓</span>
                          </div>
                          <p className="text-xs text-muted font-medium">This job portal is closed. Chat is locked.</p>
                        </div>
                      )}
                    </section>

                    <section className="bg-slate-50 p-4 rounded-2xl border-2 border-slate-200">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-muted mb-3">Details</h3>
                      <div className="space-y-1.5 text-xs font-medium text-slate-600">
                        {selectedJob.description && <p className="leading-relaxed">{selectedJob.description}</p>}
                        {selectedJob.location && <p>📍 {selectedJob.location}</p>}
                        {selectedJob.client_name && <p>👤 Client: {selectedJob.client_name}</p>}
                        {selectedJob.pro_name && <p>🔧 Pro: {selectedJob.pro_name}</p>}
                      </div>
                    </section>
                  </div>
                </div>

                {/* Chat Panel */}
                <div className={`${mobileTab === 'info' ? 'hidden' : 'flex'} sm:flex flex-col w-full sm:w-1/2 bg-slate-50`}>
                  <div className="flex-1 p-4 sm:p-6 overflow-y-auto space-y-3">
                    {messages.length === 0 ? (
                      <div className="h-full flex flex-col items-center justify-center text-center p-8">
                        <div className="w-14 h-14 bg-blue-light text-blue-primary rounded-2xl flex items-center justify-center mb-3"><MessageSquare size={28} /></div>
                        <h4 className="font-bold text-ink mb-1 text-sm">{isLocked ? 'Chat Locked' : 'No messages yet'}</h4>
                        <p className="text-xs text-muted font-medium">{isLocked ? 'This job is complete.' : 'Start the conversation.'}</p>
                      </div>
                    ) : messages.map((msg, i) => {
                      const isMe = String(msg.sender_id) === String(user?.id);
                      const showAvatar = i === 0 || messages[i-1].sender_id !== msg.sender_id;
                      return (
                        <div key={msg.id} className={`flex flex-col ${isMe ? 'items-end' : 'items-start'}`}>
                          {showAvatar && <div className={`text-[10px] font-black uppercase tracking-widest mb-1 px-1 ${isMe ? 'text-blue-primary' : 'text-muted'}`}>{isMe ? 'You' : (msg.sender_name || 'Specialist')}</div>}
                          <div className={`max-w-[85%] p-3 sm:p-4 rounded-2xl shadow-sm ${isMe ? 'bg-ink text-white rounded-tr-none' : 'bg-white border-2 border-border text-ink rounded-tl-none'}`}>
                            <p className="text-sm font-medium leading-relaxed">{msg.content}</p>
                            <div className={`text-[9px] mt-1.5 ${isMe ? 'text-white/40' : 'text-muted'}`}>{new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                          </div>
                        </div>
                      );
                    })}
                    <div ref={chatEndRef} />
                  </div>

                  {/* Chat input or lock banner */}
                  {isLocked ? (
                    <div className="p-4 border-t border-blue-primary/20 bg-white shrink-0">
                      <div className="flex items-center justify-center gap-2 p-3 bg-slate-100 border border-slate-200 rounded-2xl text-slate-500">
                        <Lock size={14} />
                        <span className="text-xs font-bold">Chat locked — job is complete</span>
                      </div>
                    </div>
                  ) : (
                    <form onSubmit={handleSendMessage} className="p-3 sm:p-5 border-t border-blue-primary/20 bg-white safe-bottom shrink-0">
                      <div className="flex gap-2">
                        <input type="text" placeholder="Type a message..." className="flex-1 p-3 bg-paper border-2 border-border rounded-2xl font-medium outline-none focus:border-blue-primary text-sm" value={newMessage} onChange={e => setNewMessage(e.target.value)} />
                        <button type="submit" disabled={!newMessage.trim()} className="bg-ink text-white p-3 rounded-2xl hover:bg-blue-primary disabled:opacity-40 transition-all shrink-0"><Send size={18} /></button>
                      </div>
                    </form>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── ADD WORK MODAL ── */}
      <AnimatePresence>
        {showWorkModal && (
          <div className="fixed inset-0 z-[110] flex items-end sm:items-center justify-center p-0 sm:p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setShowWorkModal(false)} className="absolute inset-0 bg-ink/60 backdrop-blur-sm" />
            <motion.div
              initial={{ y: '100%', opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: '100%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="relative bg-white border-t border-t-blue-primary/30 sm:border sm:border-blue-primary/30 p-6 sm:p-8 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-md max-h-[90vh] overflow-y-auto"
            >
              <div className="w-12 h-1.5 bg-border rounded-full mx-auto mb-4 sm:hidden" />
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl sm:text-2xl font-bold">Add Portfolio Work</h2>
                <button onClick={() => setShowWorkModal(false)} className="p-2 hover:bg-paper rounded-xl"><X size={22} /></button>
              </div>
              <form onSubmit={props.handleAddWork} className="space-y-4">
                <div className="space-y-1">
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-muted">Project Title</label>
                  <input type="text" required placeholder="e.g. Bathroom Renovation" className="input-brutal" value={workTitle} onChange={e => setWorkTitle(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-muted">Description</label>
                  <textarea required placeholder="Describe what you did..." className="input-brutal h-24 resize-none" value={workDesc} onChange={e => setWorkDesc(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-muted">Upload Image / Video / Document / PDF</label>
                  <div className="flex items-center gap-3">
                    <label className="flex-1 cursor-pointer">
                      <div className={`w-full p-3 border-2 border-dashed rounded-xl flex items-center justify-center gap-2 font-bold text-xs transition-all ${workFile || workImage ? 'border-blue-primary bg-blue-light text-blue-primary' : 'border-border bg-paper hover:border-blue-primary text-muted'}`}>
                        <Upload size={16} />
                        <span className="truncate max-w-[150px]">{workFile ? workFile.name : workImage ? 'File selected ✓' : 'Choose File to Upload'}</span>
                      </div>
                      <input type="file" accept="image/*,video/*,.pdf,.doc,.docx" className="hidden" onChange={e => {
                        const file = e.target.files?.[0];
                        if (file) {
                          setWorkFile(file);
                          if (file.type.startsWith('image/')) {
                            const r = new FileReader(); r.onloadend = () => setWorkImage(r.result as string); r.readAsDataURL(file);
                          } else if (file.type.startsWith('video/')) { setWorkImage('video:' + file.name); }
                          else { setWorkImage('doc:' + file.name); }
                        }
                      }} />
                    </label>
                    {workImage?.startsWith('data:image') && <img src={workImage} className="w-14 h-14 rounded-xl object-cover border border-blue-primary/20 shrink-0" alt="Preview" />}
                    {workImage?.startsWith('video:') && <div className="w-14 h-14 rounded-xl border border-blue-primary/20 flex flex-col items-center justify-center bg-blue-light shrink-0"><Play size={20} className="text-blue-primary" /><span className="text-[8px] font-bold text-muted mt-0.5">VIDEO</span></div>}
                    {workImage?.startsWith('doc:') && <div className="w-14 h-14 rounded-xl border border-blue-primary/20 flex flex-col items-center justify-center bg-paper shrink-0"><FileText size={20} className="text-muted" /><span className="text-[8px] font-bold text-muted mt-0.5">DOC</span></div>}
                    {(workFile || workImage) && <button type="button" onClick={() => { setWorkFile(null); setWorkImage(''); }} className="p-2 text-red-400 hover:bg-red-50 rounded-lg shrink-0"><X size={16} /></button>}
                  </div>
                  {workFile && <p className="text-[10px] text-muted font-medium">{workFile.name} · {(workFile.size/1024/1024).toFixed(2)} MB</p>}
                </div>
                <div className="flex gap-3 pt-2">
                  <button type="submit" className="flex-1 btn-primary py-4">Add to Portfolio</button>
                  <button type="button" onClick={() => setShowWorkModal(false)} className="flex-1 btn-secondary py-4">Cancel</button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── DELETE ACCOUNT MODAL ── */}
      <AnimatePresence>
        {showDeleteModal && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setShowDeleteModal(false)} className="absolute inset-0 bg-ink/90 backdrop-blur-md" />
            <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }} className="relative bg-white border-4 border-red-500 p-8 rounded-[32px] shadow-2xl max-w-md w-full text-center">
              <div className="w-16 h-16 bg-red-500/10 text-red-500 rounded-2xl flex items-center justify-center mx-auto mb-5"><AlertTriangle size={36} /></div>
              <h2 className="text-2xl font-bold mb-3">Delete Account?</h2>
              <p className="text-muted font-medium mb-7 text-sm">This is permanent. All your data will be deleted forever.</p>
              <div className="flex flex-col gap-3">
                <button onClick={handleDeleteAccount} className="w-full bg-red-500 text-white py-4 rounded-2xl font-bold text-lg hover:bg-red-600 transition-all">Yes, Delete Forever</button>
                <button onClick={() => setShowDeleteModal(false)} className="w-full btn-secondary py-4">Cancel</button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}
