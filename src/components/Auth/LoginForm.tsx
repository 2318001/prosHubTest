// FILE: src/components/Auth/LoginForm.tsx — Email + password input sub-component for the login step.

import React from 'react';

interface LoginFormProps {
  email: string;
  setEmail: (val: string) => void;
  password: string;
  setPassword: (val: string) => void;
  isLoading: boolean;
  onForgot: () => void;
}

/**
 * LOGIN FORM SUB-COMPONENT
 * Displays the email and password fields for the sign-in flow.
 */
export default function LoginForm({ email, setEmail, password, setPassword, isLoading, onForgot }: LoginFormProps) {
  return (
    <>
      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Email Address</label>
        <input 
          type="email" required 
          placeholder="name@example.com"
          className="input-brutal"
          value={email} onChange={e => setEmail(e.target.value)}
        />
      </div>
      
      <div>
        <div className="flex justify-between items-center mb-1">
          <label className="block text-xs font-bold uppercase tracking-wider text-muted">Password</label>
          <button 
            type="button"
            onClick={onForgot}
            className="text-[10px] font-bold uppercase tracking-wider text-blue-primary hover:underline"
          >
            Forgot Password?
          </button>
        </div>
        <input 
          type="password" required 
          placeholder="••••••••"
          className="input-brutal"
          value={password} onChange={e => setPassword(e.target.value)}
        />
      </div>
    </>
  );
}
