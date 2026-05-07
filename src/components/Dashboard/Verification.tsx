// FILE: src/components/Dashboard/Verification.tsx — Identity verification flow for pros.
// Multi-step: upload ID → cert → exp doc → submit. Sets is_verified=50 (partial); admin promotes to 100.
// FIX: docs state is passed up via onDocsChange so Dashboard.tsx can upload the actual File objects.

import React from 'react';
import { ShieldCheck, Upload, CheckCircle, AlertTriangle, Clock } from 'lucide-react';
import { motion } from 'motion/react';

export interface VerificationDocs {
  idType: string;
  idNumber: string;
  idFile: File | null;
  certFile: File | null;
  expFile: File | null;
}

interface VerificationProps {
  user: any;
  isVerifying: boolean;
  handleVerification: (docs: VerificationDocs) => void;
  onStartStripeVerification: () => void;
}

export default function Verification({ user, isVerifying, handleVerification, onStartStripeVerification }: VerificationProps) {
  const [step, setStep] = React.useState(1);
  const [docs, setDocs] = React.useState<VerificationDocs>({
    idType: 'Passport',
    idNumber: '',
    idFile: null,
    certFile: null,
    expFile: null,
  });

  const handleFileChange = (field: keyof VerificationDocs, file: File | undefined) => {
    if (file) setDocs(prev => ({ ...prev, [field]: file }));
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleVerification(docs);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-10">
      <div className="text-center">
        <div className="w-20 h-20 bg-blue-light text-blue-primary rounded-3xl flex items-center justify-center mx-auto mb-6 border-2 border-blue-primary/20">
          <ShieldCheck size={40} />
        </div>
        <h1 className="text-4xl font-bold tracking-tight mb-4">Professional Verification</h1>
        <p className="text-muted font-medium max-w-lg mx-auto">Complete your professional profile to earn the "Verified Pro" badge and unlock higher limits.</p>
      </div>

      {user?.is_verified >= 100 ? (
        <div className="card-brutal p-10 text-center bg-green-50/30 border-green-500/30">
          <div className="w-16 h-16 bg-green-500 text-white rounded-full flex items-center justify-center mx-auto mb-6 shadow-lg shadow-green-500/20">
            <CheckCircle size={32} />
          </div>
          <h2 className="text-2xl font-bold mb-2">You are Fully Verified!</h2>
          <p className="text-muted font-medium">Your credentials have been reviewed and approved by our team.</p>
        </div>
      ) : Number(user?.is_verified) === 50 ? (
        <div className="card-brutal p-10 text-center bg-amber-50/30 border-amber-300/50 space-y-4">
          <div className="w-16 h-16 bg-amber-400 text-white rounded-full flex items-center justify-center mx-auto shadow-lg shadow-amber-400/20">
            <Clock size={32} />
          </div>
          <h2 className="text-2xl font-bold text-amber-700">Documents Under Review</h2>
          <p className="text-muted font-medium max-w-md mx-auto">Our team is reviewing your documents. This usually takes up to 24 hours. You'll receive a notification once the review is complete.</p>
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-amber-100 border border-amber-300 rounded-full">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span className="text-xs font-bold text-amber-700 uppercase tracking-widest">Pending Admin Review</span>
          </div>
        </div>
      ) : (
        <div className="space-y-10">
          {/* Show rejection reason prominently if admin rejected */}
          {user?.is_verified === 0 && user?.rejection_reason && (
            <div className="card-brutal p-6 bg-red-50/50 border-red-300 space-y-4">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 bg-red-500 text-white rounded-xl flex items-center justify-center shrink-0">
                  <AlertTriangle size={20} />
                </div>
                <div>
                  <h3 className="font-black text-red-600 text-lg">Verification Rejected</h3>
                  <p className="text-sm text-red-500 font-medium mt-1">{user.rejection_reason}</p>
                </div>
              </div>
              <div className="p-3 bg-white border border-red-200 rounded-xl">
                <p className="text-xs font-bold text-muted">Please fix the issue above, then re-upload your documents and resubmit below.</p>
              </div>
            </div>
          )}

          <div className="space-y-6">
            {/* Progress Bar */}
            <div className="flex gap-2 mb-8">
              {[1, 2, 3].map(i => (
                <div key={i} className={`h-2 flex-1 rounded-full transition-all ${step >= i ? 'bg-blue-primary' : 'bg-border'}`} />
              ))}
            </div>

            <form onSubmit={onSubmit} className="card-brutal p-6 sm:p-10 space-y-8">
              {step === 1 && (
                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-8">
                  <div className="flex items-center gap-4 mb-4">
                    <div className="w-10 h-10 bg-ink text-white rounded-xl flex items-center justify-center font-bold">1</div>
                    <h2 className="text-xl font-bold uppercase tracking-tight">Identity Verification</h2>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8">
                    <div className="space-y-3">
                      <label className="block text-xs font-bold uppercase tracking-widest text-muted">ID Type</label>
                      <select
                        className="input-brutal"
                        value={docs.idType}
                        onChange={e => setDocs({ ...docs, idType: e.target.value })}
                      >
                        <option>Passport</option>
                        <option>Driver's License</option>
                        <option>National ID Card</option>
                      </select>
                    </div>
                    <div className="space-y-3">
                      <label className="block text-xs font-bold uppercase tracking-widest text-muted">ID Number</label>
                      <input
                        type="text"
                        placeholder="e.g. G1234567"
                        className="input-brutal"
                        value={docs.idNumber}
                        onChange={e => setDocs({ ...docs, idNumber: e.target.value })}
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-3">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Upload ID Photo</label>
                    <div className={`border-4 border-dashed rounded-[32px] p-8 text-center transition-all cursor-pointer group bg-paper ${docs.idFile ? 'border-green-500 bg-green-50/20' : 'border-border hover:border-blue-primary'}`}>
                      <input type="file" className="hidden" id="id-upload" accept="image/*,.pdf" onChange={e => handleFileChange('idFile', e.target.files?.[0])} />
                      <label htmlFor="id-upload" className="cursor-pointer">
                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-4 border-2 transition-all ${docs.idFile ? 'bg-green-500 text-white border-green-500' : 'bg-white border-border group-hover:border-blue-primary'}`}>
                          {docs.idFile ? <CheckCircle size={20} /> : <Upload size={20} className="text-muted group-hover:text-blue-primary" />}
                        </div>
                        <div className="font-bold">{docs.idFile ? docs.idFile.name : 'Click to upload ID'}</div>
                        {!docs.idFile && <p className="text-xs text-muted mt-1">JPG, PNG or PDF accepted</p>}
                      </label>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => setStep(2)}
                    disabled={!docs.idNumber.trim() || !docs.idFile}
                    className="w-full btn-primary py-4 disabled:opacity-50"
                  >
                    Next: Professional Credentials
                  </button>
                </motion.div>
              )}

              {step === 2 && (
                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-8">
                  <div className="flex items-center gap-4 mb-4">
                    <div className="w-10 h-10 bg-ink text-white rounded-xl flex items-center justify-center font-bold">2</div>
                    <h2 className="text-xl font-bold uppercase tracking-tight">Skills & Degrees</h2>
                  </div>
                  <p className="text-sm text-muted font-medium">Upload your degree, diploma, or professional certification relevant to your field.</p>

                  <div className="space-y-3">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Upload Certificate / Degree</label>
                    <div className={`border-4 border-dashed rounded-[32px] p-8 text-center transition-all cursor-pointer group bg-paper ${docs.certFile ? 'border-green-500 bg-green-50/20' : 'border-border hover:border-blue-primary'}`}>
                      <input type="file" className="hidden" id="cert-upload" accept="image/*,.pdf,.doc,.docx" onChange={e => handleFileChange('certFile', e.target.files?.[0])} />
                      <label htmlFor="cert-upload" className="cursor-pointer">
                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-4 border-2 transition-all ${docs.certFile ? 'bg-green-500 text-white border-green-500' : 'bg-white border-border group-hover:border-blue-primary'}`}>
                          {docs.certFile ? <CheckCircle size={20} /> : <Upload size={20} className="text-muted group-hover:text-blue-primary" />}
                        </div>
                        <div className="font-bold">{docs.certFile ? docs.certFile.name : 'Click to upload Certificate'}</div>
                        {!docs.certFile && <p className="text-xs text-muted mt-1">JPG, PNG, PDF or Word accepted</p>}
                      </label>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <button type="button" onClick={() => setStep(1)} className="flex-1 btn-secondary py-4">Back</button>
                    <button
                      type="button"
                      onClick={() => setStep(3)}
                      disabled={!docs.certFile}
                      className="flex-1 btn-primary py-4 disabled:opacity-50"
                    >
                      Next: Experience Proof
                    </button>
                  </div>
                </motion.div>
              )}

              {step === 3 && (
                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-8">
                  <div className="flex items-center gap-4 mb-4">
                    <div className="w-10 h-10 bg-ink text-white rounded-xl flex items-center justify-center font-bold">3</div>
                    <h2 className="text-xl font-bold uppercase tracking-tight">Experience Proof</h2>
                  </div>
                  <p className="text-sm text-muted font-medium">Upload reference letters, work contracts, or experience certificates from previous employers.</p>

                  <div className="space-y-3">
                    <label className="block text-xs font-bold uppercase tracking-widest text-muted">Upload Experience Document <span className="text-muted/60 normal-case font-medium">(optional)</span></label>
                    <div className={`border-4 border-dashed rounded-[32px] p-8 text-center transition-all cursor-pointer group bg-paper ${docs.expFile ? 'border-green-500 bg-green-50/20' : 'border-border hover:border-blue-primary'}`}>
                      <input type="file" className="hidden" id="exp-upload" accept="image/*,.pdf,.doc,.docx" onChange={e => handleFileChange('expFile', e.target.files?.[0])} />
                      <label htmlFor="exp-upload" className="cursor-pointer">
                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-4 border-2 transition-all ${docs.expFile ? 'bg-green-500 text-white border-green-500' : 'bg-white border-border group-hover:border-blue-primary'}`}>
                          {docs.expFile ? <CheckCircle size={20} /> : <Upload size={20} className="text-muted group-hover:text-blue-primary" />}
                        </div>
                        <div className="font-bold">{docs.expFile ? docs.expFile.name : 'Click to upload Document'}</div>
                        {!docs.expFile && <p className="text-xs text-muted mt-1">Optional — JPG, PNG, PDF or Word</p>}
                      </label>
                    </div>
                  </div>

                  <div className="p-4 bg-blue-light/50 border border-blue-primary/20 rounded-2xl space-y-1">
                    <p className="text-xs font-bold text-blue-primary uppercase tracking-wider">Summary</p>
                    <p className="text-sm font-medium">{docs.idType}: {docs.idNumber}</p>
                    <p className="text-sm font-medium">ID: {docs.idFile?.name}</p>
                    <p className="text-sm font-medium">Certificate: {docs.certFile?.name}</p>
                    {docs.expFile && <p className="text-sm font-medium">Experience: {docs.expFile?.name}</p>}
                  </div>

                  <div className="flex gap-4">
                    <button type="button" onClick={() => setStep(2)} className="flex-1 btn-secondary py-4">Back</button>
                    <button
                      type="submit"
                      disabled={isVerifying || !docs.idFile || !docs.certFile}
                      className="flex-1 btn-primary py-4 disabled:opacity-50"
                    >
                      {isVerifying ? (
                        <span className="flex items-center justify-center gap-2">
                          <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Submitting...
                        </span>
                      ) : 'Submit All for Review'}
                    </button>
                  </div>
                </motion.div>
              )}
            </form>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
        <div className="p-6 bg-white border-2 border-border rounded-2xl space-y-3">
          <div className="text-blue-primary"><ShieldCheck size={24} /></div>
          <h3 className="font-bold">Secure</h3>
          <p className="text-xs text-muted font-medium">Bank-level encryption for your documents.</p>
        </div>
        <div className="p-6 bg-white border-2 border-border rounded-2xl space-y-3">
          <div className="text-gold"><Clock size={24} /></div>
          <h3 className="font-bold">Fast</h3>
          <p className="text-xs text-muted font-medium">Most reviews completed within 24 hours.</p>
        </div>
        <div className="p-6 bg-white border-2 border-border rounded-2xl space-y-3">
          <div className="text-red-500"><AlertTriangle size={24} /></div>
          <h3 className="font-bold">Required</h3>
          <p className="text-xs text-muted font-medium">Verification is needed to access premium features.</p>
        </div>
      </div>
    </div>
  );
}
