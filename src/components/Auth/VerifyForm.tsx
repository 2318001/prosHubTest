// FILE: src/components/Auth/VerifyForm.tsx — 6-digit code input for 2FA login verification after password is accepted.

import React from 'react';

interface VerifyFormProps {
  verificationCode: string;
  setVerificationCode: (val: string) => void;
  setStep: (val: 'form' | 'verify' | 'forgot' | 'reset') => void;
  onResend: () => void;
}

/**
 * VERIFY FORM SUB-COMPONENT
 * Handles the 6-digit code entry for account verification.
 */
export default function VerifyForm({ verificationCode, setVerificationCode, setStep, onResend }: VerifyFormProps) {
  return (
    <div>
      <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Verification Code</label>
      <input 
        type="text" required 
        placeholder="123456"
        maxLength={6}
        className="w-full p-4 bg-paper border-2 border-border rounded-xl focus:border-blue-primary outline-none transition-colors font-black text-center text-3xl tracking-[0.5em]"
        value={verificationCode} onChange={e => setVerificationCode(e.target.value)}
      />
      <div className="flex justify-between mt-2">
        <button 
          type="button" 
          onClick={() => setStep('form')}
          className="text-xs font-bold text-muted hover:text-ink hover:underline"
        >
          Back to login
        </button>
        <button 
          type="button"
          onClick={onResend}
          className="text-xs font-bold text-blue-primary hover:underline"
        >
          Resend Code
        </button>
      </div>
    </div>
  );
}
