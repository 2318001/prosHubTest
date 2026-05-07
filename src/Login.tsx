// FILE: src/Login.tsx — Authentication page. Handles login (2-step: password → email code), register, forgot password, and reset password flows.

import React, { useState } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

// Import sub-components
import LoginForm from './components/Auth/LoginForm';
import RegisterForm from './components/Auth/RegisterForm';
import VerifyForm from './components/Auth/VerifyForm';

/**
 * AUTHENTICATION PAGE
 * This component handles the entire login and registration flow.
 * It manages state for switching between Login and Register modes, 
 * and handles the two-step verification process (form input -> code verification).
 */
export default function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [step, setStep] = useState<'form' | 'verify' | 'forgot' | 'reset'>('form');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [name, setName] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [role, setRole] = useState<'client' | 'pro'>('client');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [location, setLocation] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const handleResendCode = async () => {
    setError('');
    setMessage('');
    setIsLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to resend code');
      setMessage('A new verification code has been sent.');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setIsLoading(true);
    
    try {
      if (step === 'forgot') {
        const res = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to send reset code');
        setMessage(data.message);
        setStep('reset');
      } else if (step === 'reset') {
        const res = await fetch('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, code: verificationCode, newPassword }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to reset password');
        setMessage('Password reset successful! You can now log in.');
        setStep('form');
        setIsRegister(false);
      } else if (isRegister) {
        if (role === 'pro' && !selectedCategory) {
          throw new Error('Please select a primary category');
        }
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            email, 
            password, 
            name, 
            role, 
            skills: role === 'pro' ? [selectedCategory] : [],
            location
          }),
        });
        
        let data;
        const contentType = res.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          data = await res.json();
        } else {
          const text = await res.text();
          throw new Error(text || 'Server error occurred');
        }

        if (!res.ok) throw new Error(data.error || 'Registration failed');
        
        login(data.accessToken, data.user, data.refreshToken);
        const search = searchParams.get('search');
        navigate(search ? `/dashboard?search=${search}` : '/dashboard');
      } else {
        if (step === 'form') {
          const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
          });
          
          let data;
          const contentType = res.headers.get("content-type");
          if (contentType && contentType.indexOf("application/json") !== -1) {
            data = await res.json();
          } else {
            const text = await res.text();
            throw new Error(text || 'Server error occurred');
          }
          
          if (!res.ok) throw new Error(data.error || 'Login failed');
          
          // FIX: Admin users get token directly — no email verification needed
          if (data.adminDirect && data.accessToken) {
            login(data.accessToken, data.user, data.refreshToken);
            const search = searchParams.get('search');
            navigate(search ? `/dashboard?search=${search}` : '/dashboard');
          } else {
            setStep('verify');
          }
        } else {
          const res = await fetch('/api/auth/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code: verificationCode }),
          });
          
          let data;
          const contentType = res.headers.get("content-type");
          if (contentType && contentType.indexOf("application/json") !== -1) {
            data = await res.json();
          } else {
            const text = await res.text();
            throw new Error(text || 'Server error occurred');
          }
          
          if (!res.ok) throw new Error(data.error || 'Verification failed');
          
          login(data.accessToken, data.user, data.refreshToken);
          const search = searchParams.get('search');
          navigate(search ? `/dashboard?search=${search}` : '/dashboard');
        }
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-paper">
      <div className="card-brutal p-8 max-w-md w-full relative">
        <Link 
          to="/" 
          className="inline-flex items-center gap-2 text-sm font-bold text-muted hover:text-ink transition-colors mb-6 group"
        >
          <ArrowLeft size={16} className="transition-transform group-hover:-translate-x-1" />
          Back to Home
        </Link>

        <h2 className="text-3xl font-bold mb-2 tracking-tight">
          {step === 'verify' ? 'Verify Account' : 
           step === 'forgot' ? 'Reset Password' :
           step === 'reset' ? 'New Password' :
           isRegister ? 'Join ProsHub' : 'Welcome Back'}
        </h2>
        <p className="text-muted mb-6 text-sm">
          {step === 'verify' 
            ? `We sent a 6-digit code to ${email}. Please check your inbox.` 
            : step === 'forgot' ? 'Enter your email and we will send you a reset code.'
            : step === 'reset' ? `Enter the 6-digit code sent to ${email} and your new password.`
            : isRegister ? 'Create an account to start hiring or earning.' : 'Log in to manage your jobs.'}
        </p>

        {error && (
          <div className="bg-red-50 text-red-500 p-3 rounded-lg text-sm mb-4 border border-red-100 font-medium">
            {error}
          </div>
        )}

        {message && (
          <div className="bg-green-50 text-green-600 p-3 rounded-lg text-sm mb-4 border border-green-100 font-medium">
            {message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {step === 'form' ? (
            isRegister ? (
              <RegisterForm 
                name={name} setName={setName} email={email} setEmail={setEmail} 
                password={password} setPassword={setPassword} role={role} setRole={setRole} 
                selectedCategory={selectedCategory} setSelectedCategory={setSelectedCategory} 
                location={location} setLocation={setLocation}
              />
            ) : (
              <LoginForm 
                email={email} setEmail={setEmail} password={password} 
                setPassword={setPassword} isLoading={isLoading} 
                onForgot={() => setStep('forgot')}
              />
            )
          ) : step === 'verify' ? (
            <VerifyForm 
              verificationCode={verificationCode} 
              setVerificationCode={setVerificationCode} 
              setStep={setStep} 
              onResend={handleResendCode}
            />
          ) : step === 'forgot' ? (
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Email Address</label>
              <input 
                type="email" required 
                placeholder="name@example.com"
                className="input-brutal"
                value={email} onChange={e => setEmail(e.target.value)}
              />
              <button 
                type="button"
                onClick={() => setStep('form')}
                className="mt-2 text-xs font-bold text-blue-primary hover:underline"
              >
                Back to Login
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Reset Code</label>
                <input 
                  type="text" required 
                  placeholder="6-digit code"
                  className="input-brutal"
                  value={verificationCode} onChange={e => setVerificationCode(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">New Password</label>
                <input 
                  type="password" required 
                  placeholder="••••••••"
                  className="input-brutal"
                  value={newPassword} onChange={e => setNewPassword(e.target.value)}
                />
              </div>
              <button 
                type="button"
                onClick={() => setStep('forgot')}
                className="mt-2 text-xs font-bold text-blue-primary hover:underline"
              >
                Resend Code
              </button>
            </div>
          )}

          <button type="submit" disabled={isLoading} className="w-full bg-ink text-white p-4 rounded-xl font-black text-lg hover:bg-blue-primary transition-all transform hover:-translate-y-1 active:translate-y-0 shadow-lg mt-4 disabled:opacity-50">
            {isLoading ? 'Processing...' : 
             step === 'verify' ? 'Verify & Sign In' : 
             step === 'forgot' ? 'Send Reset Code' :
             step === 'reset' ? 'Update Password' :
             isRegister ? 'Create Account' : 'Sign In'}
          </button>
        </form>

        {step === 'form' && (
          <button 
            onClick={() => setIsRegister(!isRegister)}
            className="w-full mt-6 text-sm font-bold text-muted hover:text-blue-primary transition-colors"
          >
            {isRegister ? 'Already have an account? Log In' : "Don't have an account? Sign Up"}
          </button>
        )}
      </div>
    </div>
  );
}
