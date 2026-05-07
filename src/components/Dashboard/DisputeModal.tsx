// FILE: src/components/Dashboard/DisputeModal.tsx
// PURPOSE: Modal for a client or pro to raise a dispute on an active job.
//          Also shows the admin dispute resolution form.

import React, { useState } from 'react';
import { AlertTriangle, X, Scale } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Job } from '../../types';

interface DisputeModalProps {
  job: Job;
  token: string;
  userId: string;
  isAdmin: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function DisputeModal({ job, token, userId, isAdmin, onClose, onSuccess }: DisputeModalProps) {
  const [reason, setReason] = useState('');
  const [resolution, setResolution] = useState('');
  const [outcome, setOutcome] = useState<'favour_client' | 'favour_pro' | 'cancelled'>('cancelled');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const isDisputed = job.status === 'disputed';

  const handleRaiseDispute = async () => {
    if (reason.trim().length < 10) { setError('Please provide more detail (min 10 characters).'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/jobs/${job.id}/dispute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ reason }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Failed to raise dispute'); return; }
      onSuccess();
      onClose();
    } catch { setError('Network error. Please try again.'); }
    finally { setLoading(false); }
  };

  const handleResolveDispute = async () => {
    if (resolution.trim().length < 10) { setError('Please describe the resolution (min 10 characters).'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/jobs/${job.id}/resolve-dispute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ resolution, outcome }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Failed to resolve dispute'); return; }
      onSuccess();
      onClose();
    } catch { setError('Network error. Please try again.'); }
    finally { setLoading(false); }
  };

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        style={{ background: 'rgba(0,0,0,0.5)' }}
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.div
          className="bg-white rounded-3xl p-6 sm:p-8 w-full max-w-lg shadow-2xl"
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
          onClick={e => e.stopPropagation()}
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-amber-100 text-amber-600 rounded-xl flex items-center justify-center">
                {isAdmin && isDisputed ? <Scale size={20} /> : <AlertTriangle size={20} />}
              </div>
              <div>
                <h2 className="text-lg font-bold">
                  {isAdmin && isDisputed ? 'Resolve Dispute' : isDisputed ? 'Dispute In Progress' : 'Raise a Dispute'}
                </h2>
                <p className="text-xs text-muted font-medium">{job.title}</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-paper rounded-xl transition-colors"><X size={18} /></button>
          </div>

          {/* Already disputed — show info to non-admin */}
          {isDisputed && !isAdmin && (
            <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 mb-4">
              <p className="text-sm font-semibold text-amber-800">A dispute is already open</p>
              <p className="text-xs text-amber-700 mt-1">{job.dispute_reason}</p>
              <p className="text-xs text-muted mt-2">An admin will review and resolve this shortly. You'll receive a notification with the outcome.</p>
            </div>
          )}

          {/* Admin resolve form */}
          {isAdmin && isDisputed && (
            <div className="space-y-4">
              <div className="bg-red-50 border border-red-200 rounded-2xl p-4">
                <p className="text-xs font-bold text-red-700 uppercase tracking-widest mb-1">Reason raised</p>
                <p className="text-sm text-red-800">{job.dispute_reason}</p>
                <p className="text-xs text-muted mt-1">Raised by: {job.dispute_raised_by === job.client_id ? job.client_name || 'Client' : job.pro_name || 'Pro'}</p>
              </div>

              <div>
                <label className="block text-xs font-bold mb-2 uppercase tracking-widest">Resolution notes</label>
                <textarea
                  className="input-brutal w-full !rounded-2xl resize-none"
                  rows={3}
                  placeholder="Describe the resolution and reasoning..."
                  value={resolution}
                  onChange={e => setResolution(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-bold mb-2 uppercase tracking-widest">Outcome</label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { val: 'favour_client', label: 'Favour Client', colour: 'border-blue-primary text-blue-primary bg-blue-light' },
                    { val: 'favour_pro', label: 'Favour Pro', colour: 'border-green-primary text-green-primary bg-green-light' },
                    { val: 'cancelled', label: 'Cancel Job', colour: 'border-red-400 text-red-600 bg-red-50' },
                  ].map(opt => (
                    <button
                      key={opt.val}
                      onClick={() => setOutcome(opt.val as typeof outcome)}
                      className={`p-2 rounded-xl text-xs font-bold border-2 transition-all ${outcome === opt.val ? opt.colour : 'border-border text-muted'}`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {error && <p className="text-red-500 text-xs font-medium">{error}</p>}

              <button
                onClick={handleResolveDispute}
                disabled={loading}
                className="w-full py-3 bg-blue-primary text-white rounded-2xl font-bold hover:bg-blue-dark transition-colors disabled:opacity-50"
              >
                {loading ? 'Resolving...' : 'Resolve Dispute'}
              </button>
            </div>
          )}

          {/* Raise dispute form */}
          {!isDisputed && (
            <div className="space-y-4">
              <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 text-sm text-amber-800">
                <p className="font-semibold mb-1">Before raising a dispute</p>
                <p className="text-xs">Try to resolve the issue directly in the chat. Disputes are reviewed by an admin and may take up to 48 hours.</p>
              </div>

              <div>
                <label className="block text-xs font-bold mb-2 uppercase tracking-widest">What is the issue?</label>
                <textarea
                  className="input-brutal w-full !rounded-2xl resize-none"
                  rows={4}
                  placeholder="Describe the problem clearly. Include relevant details about what was agreed vs what happened..."
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                />
                <p className="text-xs text-muted mt-1">{reason.length}/1000 characters</p>
              </div>

              {error && <p className="text-red-500 text-xs font-medium">{error}</p>}

              <button
                onClick={handleRaiseDispute}
                disabled={loading}
                className="w-full py-3 bg-amber-500 text-white rounded-2xl font-bold hover:bg-amber-600 transition-colors disabled:opacity-50"
              >
                {loading ? 'Submitting...' : 'Raise Dispute'}
              </button>
            </div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
