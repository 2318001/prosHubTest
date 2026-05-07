// FILE: src/components/Dashboard/WithdrawModal.tsx — UI placeholder for pro earnings withdrawal. Actual payment processing (e.g. Stripe) not yet implemented.

import React, { useState } from 'react';
import { X, Landmark, CreditCard, ArrowRight, CheckCircle2, AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface WithdrawModalProps {
  isOpen: boolean;
  onClose: () => void;
  balance: number;
  user: any;
  onWithdraw: (amount: number, method: string) => Promise<boolean>;
}

export default function WithdrawModal({ isOpen, onClose, balance, user, onWithdraw }: WithdrawModalProps) {
  const [amount, setAmount] = useState('');
  const [method, setMethod] = useState('bank_transfer');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [step, setStep] = useState<'form' | 'success'>('form');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const numAmount = parseFloat(amount);
    if (isNaN(numAmount) || numAmount < 10 || numAmount > balance) return;

    setIsSubmitting(true);
    const success = await onWithdraw(numAmount, method);
    setIsSubmitting(false);

    if (success) {
      setStep('success');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/60 backdrop-blur-sm">
      <motion.div 
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="bg-paper border border-blue-primary/20 rounded-[40px] w-full max-w-md overflow-hidden shadow-[0_20px_60px_#2563eb20]"
      >
        <div className="p-8">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-black uppercase tracking-tight">Withdraw Funds</h2>
            <button onClick={onClose} className="p-2 hover:bg-black/5 rounded-full transition-all">
              <X size={24} />
            </button>
          </div>

          <AnimatePresence mode="wait">
            {step === 'form' ? (
              <motion.form 
                key="form"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                onSubmit={handleSubmit} 
                className="space-y-6"
              >
                <div className="bg-blue-light/30 border-2 border-blue-primary/20 rounded-2xl p-4 flex justify-between items-center">
                  <span className="text-xs font-bold uppercase tracking-widest text-muted">Available to Withdraw</span>
                  <span className="text-xl font-black text-blue-primary">£{balance.toFixed(2)}</span>
                </div>

                <div className="space-y-4">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">Amount to Withdraw (£)</label>
                  <input 
                    type="number" 
                    required
                    min="10"
                    max={balance}
                    step="0.01"
                    className="input-brutal text-2xl font-black"
                    placeholder="0.00"
                    value={amount}
                    onChange={e => setAmount(e.target.value)}
                  />
                  {parseFloat(amount) > 500 && user?.is_verified < 100 && (
                    <div className="flex items-center gap-2 p-3 bg-red-50 text-red-500 rounded-xl border border-red-200 text-xs font-bold">
                      <AlertTriangle size={16} />
                      Identity verification is required for withdrawals over £500.
                    </div>
                  )}
                  <p className="text-[10px] font-bold text-muted italic">Minimum withdrawal: £10.00</p>
                </div>

                <div className="space-y-4">
                  <label className="block text-xs font-bold uppercase tracking-widest text-muted">Withdrawal Method</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button 
                      type="button"
                      onClick={() => setMethod('bank_transfer')}
                      className={`p-4 border-2 rounded-2xl flex flex-col items-center gap-2 transition-all ${
                        method === 'bank_transfer' ? 'border-blue-primary bg-white shadow-[0_4px_14px_#2563eb25]' : 'border-border bg-paper opacity-60'
                      }`}
                    >
                      <Landmark size={24} />
                      <span className="text-[10px] font-black uppercase tracking-widest">Bank Transfer</span>
                    </button>
                    <button 
                      type="button"
                      onClick={() => setMethod('paypal')}
                      className={`p-4 border-2 rounded-2xl flex flex-col items-center gap-2 transition-all ${
                        method === 'paypal' ? 'border-blue-primary bg-white shadow-[0_4px_14px_#2563eb25]' : 'border-border bg-paper opacity-60'
                      }`}
                    >
                      <CreditCard size={24} />
                      <span className="text-[10px] font-black uppercase tracking-widest">PayPal</span>
                    </button>
                  </div>
                </div>

                <button 
                  type="submit" 
                  disabled={isSubmitting || !amount || parseFloat(amount) < 10 || parseFloat(amount) > balance}
                  className="btn-primary w-full py-4 text-lg flex items-center justify-center gap-2"
                >
                  {isSubmitting ? 'Processing...' : (
                    <>
                      Confirm Withdrawal <ArrowRight size={20} />
                    </>
                  )}
                </button>
              </motion.form>
            ) : (
              <motion.div 
                key="success"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-10 space-y-6"
              >
                <div className="w-20 h-20 bg-green-light text-green-primary rounded-full flex items-center justify-center mx-auto mb-4 border-4 border-green-500/20">
                  <CheckCircle2 size={48} />
                </div>
                <div>
                  <h3 className="text-2xl font-black mb-2">Request Submitted!</h3>
                  <p className="text-muted font-medium">
                    Your withdrawal of £{parseFloat(amount).toFixed(2)} is being processed. 
                    Funds usually arrive within 1-3 business days.
                  </p>
                </div>
                <button 
                  onClick={onClose}
                  className="btn-secondary w-full py-4"
                >
                  Back to Dashboard
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  );
}
