// FILE: src/components/Dashboard/SubscriptionModalInline.tsx
// PURPOSE: Subscription modal — currently FREE for all pros. Future paid plans will be introduced with advance notice.
// CHANGE: Added "How it works" section with review-like cards. Improved free plan messaging.

import React from 'react';
import { X, Zap, CheckCircle, Star, Gift, Info, Crown, Bell, MessageSquare, Search, FileText } from 'lucide-react';
import { motion } from 'motion/react';

interface Props {
  onClose: () => void;
  onStartTrial: () => void;
  onSubscribe: () => void;
  subscriptionStatus: string;
  trialEndsAt?: string | null;
}

const HOW_IT_WORKS = [
  {
    icon: Search,
    title: 'Get Found',
    desc: 'Clients search by skill — your profile appears in results matching your expertise.',
    color: 'bg-blue-light text-blue-primary',
  },
  {
    icon: Bell,
    title: 'Instant Job Alerts',
    desc: 'When a client posts a job matching your skills you get a real-time notification.',
    color: 'bg-gold/10 text-gold',
  },
  {
    icon: MessageSquare,
    title: 'Negotiate & Accept',
    desc: 'Chat directly with the client, agree on a price, then accept the job.',
    color: 'bg-green-light text-green-primary',
  },
  {
    icon: Star,
    title: 'Build Reviews',
    desc: 'After each job the client can leave a review. Manage visibility from your profile.',
    color: 'bg-purple-100 text-purple-500',
  },
  {
    icon: FileText,
    title: 'Showcase Portfolio',
    desc: 'Upload photos and videos of your work. Clients see them on your public profile.',
    color: 'bg-orange-100 text-orange-500',
  },
  {
    icon: Crown,
    title: 'Get Verified',
    desc: 'Submit your ID and credentials. Verified pros get a badge that builds client trust.',
    color: 'bg-blue-light text-blue-primary',
  },
];

const PRO_FEATURES = [
  'Appear in search results for clients',
  'Receive job notifications instantly',
  'Accept unlimited job requests',
  'Full messaging & negotiation tools',
  'Build your portfolio & get reviews',
  'Upload images & videos to showcase work',
  'Live location sharing for local jobs',
];

export default function SubscriptionModalInline({ onClose, onStartTrial, subscriptionStatus, trialEndsAt }: Props) {
  const isTrial  = subscriptionStatus === 'trial';
  const isActive = subscriptionStatus === 'active';
  const trialEnd = trialEndsAt ? new Date(trialEndsAt).toLocaleDateString() : null;
  const [tab, setTab] = React.useState<'overview' | 'howItWorks'>('overview');

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[150] flex items-end sm:items-center justify-center p-0 sm:p-4"
    >
      {/* Backdrop */}
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-ink/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Sheet / Modal */}
      <motion.div
        initial={{ y: '100%', opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: '100%', opacity: 0 }}
        transition={{ type: 'spring', damping: 30, stiffness: 300 }}
        className="relative bg-white border-t border-blue-primary/20 sm:border sm:border-blue-primary/20 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-lg p-6 sm:p-8 max-h-[92vh] overflow-y-auto"
      >
        {/* Mobile drag handle */}
        <div className="w-12 h-1.5 bg-border rounded-full mx-auto mb-4 sm:hidden" />

        {/* Close button */}
        <button onClick={onClose} className="absolute top-4 right-4 sm:top-6 sm:right-6 p-2 hover:bg-paper rounded-xl transition-all">
          <X size={22} />
        </button>

        {/* Header */}
        <div className="text-center mb-5">
          <div className="w-14 h-14 bg-green-light text-green-primary rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Gift size={28} />
          </div>
          <h2 className="text-2xl sm:text-3xl font-black mb-2">
            {isTrial ? 'Trial Active' : isActive ? 'Pro Access Active' : 'ProsHub is Free!'}
          </h2>
          <p className="text-sm text-muted font-medium">
            {isTrial
              ? `Your free trial runs until ${trialEnd || 'soon'}.`
              : isActive
              ? 'You have full access to all Pro features.'
              : 'All features are completely free right now. No credit card needed.'}
          </p>
        </div>

        {/* Tab switcher */}
        <div className="flex gap-2 mb-5 p-1 bg-paper rounded-2xl border border-border">
          {(['overview', 'howItWorks'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${tab === t ? 'bg-ink text-white shadow' : 'text-muted hover:text-ink'}`}
            >
              {t === 'overview' ? 'Overview' : 'How It Works'}
            </button>
          ))}
        </div>

        {tab === 'overview' && (
          <>
            {/* Feature list */}
            <div className="space-y-2.5 mb-5">
              {PRO_FEATURES.map(f => (
                <div key={f} className="flex items-center gap-3 text-sm font-medium">
                  <CheckCircle size={16} className="text-green-primary shrink-0" />
                  {f}
                </div>
              ))}
            </div>

            {!isTrial && !isActive && (
              <div className="space-y-3">
                <button
                  onClick={onStartTrial}
                  className="w-full bg-green-primary text-white py-4 rounded-2xl font-black text-base hover:shadow-[0_6px_20px_#10b98140] transition-all flex items-center justify-center gap-2"
                >
                  <Zap size={20} /> Activate Free Access
                </button>
                <div className="p-3 bg-gold/10 border border-gold/30 rounded-xl">
                  <p className="text-[11px] text-gold font-bold text-center leading-relaxed">
                    ⚡ <strong>Coming Soon:</strong> Subscription plans will be introduced in the future.
                    Pros will be notified in advance before any charges apply.
                  </p>
                </div>
                <button onClick={onClose} className="w-full py-3 text-xs text-muted font-bold hover:text-ink transition-colors">
                  Maybe later
                </button>
              </div>
            )}

            {(isTrial || isActive) && (
              <div className="space-y-3">
                <div className={`p-4 rounded-2xl border-2 text-center ${isTrial ? 'bg-gold/10 border-gold/30 text-gold' : 'bg-green-light border-green-primary/30 text-green-primary'}`}>
                  <div className="font-black text-sm uppercase tracking-widest">
                    {isTrial ? `Trial ends ${trialEnd}` : 'Full Access Active ✓'}
                  </div>
                </div>
                <div className="p-3 bg-blue-light border border-blue-primary/20 rounded-xl">
                  <p className="text-[11px] text-blue-primary font-bold text-center leading-relaxed">
                    Subscription plans coming soon. You will be notified before any charges apply.
                  </p>
                </div>
                <button onClick={onClose} className="w-full btn-secondary py-3 text-sm">Close</button>
              </div>
            )}
          </>
        )}

        {tab === 'howItWorks' && (
          <div className="space-y-3">
            {HOW_IT_WORKS.map((item, i) => (
              <div key={i} className="flex items-start gap-4 p-4 bg-paper border border-border rounded-2xl">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${item.color}`}>
                  <item.icon size={18} />
                </div>
                <div className="min-w-0">
                  <p className="font-black text-sm mb-0.5">{item.title}</p>
                  <p className="text-xs text-muted font-medium leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
            <div className="p-3 bg-blue-light border border-blue-primary/20 rounded-xl mt-2">
              <p className="text-[11px] text-blue-primary font-bold text-center">
                <Info size={11} className="inline mr-1" />
                All features are free right now. Future subscription plans will be announced in advance.
              </p>
            </div>
            <button onClick={onClose} className="w-full btn-secondary py-3 text-sm mt-1">Got it, close</button>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
