// FILE: src/components/Dashboard/Profile.tsx
// PURPOSE: Pro/client profile editor.
//   - Pros: edit name/bio/location/skills/avatar, manage portfolio (images+videos),
//     upload verification documents, toggle profile/docs visibility, manage reviews.
//   - Clients: edit name/bio/location, delete account.
//
// KEY CHANGES (v7):
//   - Portfolio grid now shows View + Delete hover buttons.
//   - handleDeleteWork prop wires the Delete button to DELETE /api/user/completed-works/:id.
//   - File is also removed from disk on the server side.

import React from 'react';
import { Upload, Plus, X, ShieldCheck, AlertTriangle, LogOut, Eye, EyeOff, Play, FileText, Download, Star, Edit2, Trash2, Check } from 'lucide-react';

// ── ProReviewsManager ─────────────────────────────────────────────────────────
function ProReviewsManager({ user, token }: { user: any; token: string | null }) {
  const [reviews, setReviews] = React.useState<any[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [editComment, setEditComment] = React.useState('');
  const [editRating, setEditRating] = React.useState(5);

  const fetchMyReviews = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/user/reviews', { headers: { Authorization: `Bearer ${token}` } });
      if (r.ok) setReviews(await r.json());
    } catch {}
    setLoading(false);
  };

  React.useEffect(() => { fetchMyReviews(); }, [token]);

  const toggleVisibility = async (review: any) => {
    if (!token) return;
    await fetch(`/api/user/reviews/${review.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ is_private: review.is_private ? 0 : 1 }),
    });
    fetchMyReviews();
  };

  const deleteReview = async (id: string) => {
    if (!token || !window.confirm('Delete this review?')) return;
    await fetch(`/api/user/reviews/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
    fetchMyReviews();
  };

  const saveEdit = async (id: string) => {
    if (!token) return;
    await fetch(`/api/user/reviews/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ comment: editComment, rating: editRating }),
    });
    setEditingId(null);
    fetchMyReviews();
  };

  return (
    <div className="card-brutal p-6 sm:p-8 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <h3 className="font-bold uppercase tracking-widest text-xs text-muted">My Reviews</h3>
          <span className="bg-gold/10 text-gold text-[10px] font-bold px-2 py-0.5 rounded-full">Manage visibility</span>
        </div>
        {user?.avg_rating && (
          <div className="flex items-center gap-1">
            {[1,2,3,4,5].map(i => <Star key={i} size={13} fill={i <= Math.round(user.avg_rating) ? 'currentColor' : 'none'} className={i <= Math.round(user.avg_rating) ? 'text-gold' : 'text-border'} />)}
            <span className="text-xs font-bold text-muted ml-1">{user.avg_rating} ({user.review_count})</span>
          </div>
        )}
      </div>
      {loading ? (
        <p className="text-sm text-muted text-center py-4">Loading reviews...</p>
      ) : reviews.length === 0 ? (
        <p className="text-sm text-muted font-medium py-4 text-center">No reviews yet. Complete jobs to receive client reviews.</p>
      ) : (
        <div className="space-y-3">
          {reviews.map((review: any) => (
            <div key={review.id} className={`p-4 border-2 rounded-xl ${review.is_private ? 'border-border bg-paper opacity-60' : 'border-green-primary/30 bg-green-light/20'}`}>
              {editingId === review.id ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-1">
                    {[1,2,3,4,5].map(s => (
                      <button key={s} type="button" onClick={() => setEditRating(s)} className={`p-0.5 ${editRating >= s ? 'text-gold' : 'text-border'}`}>
                        <Star size={18} fill={editRating >= s ? 'currentColor' : 'none'} />
                      </button>
                    ))}
                  </div>
                  <textarea className="w-full p-2 border-2 border-border rounded-xl text-sm h-16 outline-none resize-none" value={editComment} onChange={e => setEditComment(e.target.value)} />
                  <div className="flex gap-2">
                    <button onClick={() => saveEdit(review.id)} className="flex items-center gap-1 px-3 py-1.5 bg-green-primary text-white rounded-lg text-xs font-bold"><Check size={13} /> Save</button>
                    <button onClick={() => setEditingId(null)} className="flex items-center gap-1 px-3 py-1.5 border-2 border-border rounded-lg text-xs font-bold"><X size={13} /> Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-1">
                      {[1,2,3,4,5].map(i => <Star key={i} size={13} fill={i <= review.rating ? 'currentColor' : 'none'} className={i <= review.rating ? 'text-gold' : 'text-border'} />)}
                      <span className="text-xs text-muted ml-2">{review.created_at ? new Date(review.created_at).toLocaleDateString() : ''}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full ${review.is_private ? 'bg-border text-muted' : 'bg-green-light text-green-primary'}`}>
                        {review.is_private ? 'Hidden' : 'Visible'}
                      </span>
                      <button onClick={() => toggleVisibility(review)} title={review.is_private ? 'Show to clients' : 'Hide from clients'} className="p-1.5 hover:bg-paper rounded-lg transition-all">
                        {review.is_private ? <Eye size={14} className="text-muted" /> : <EyeOff size={14} className="text-green-primary" />}
                      </button>
                      <button onClick={() => { setEditingId(review.id); setEditComment(review.comment || ''); setEditRating(review.rating); }} className="p-1.5 hover:bg-paper rounded-lg transition-all">
                        <Edit2 size={14} className="text-blue-primary" />
                      </button>
                      <button onClick={() => deleteReview(review.id)} className="p-1.5 hover:bg-red-50 rounded-lg transition-all">
                        <Trash2 size={14} className="text-red-400" />
                      </button>
                    </div>
                  </div>
                  {review.comment && <p className="text-sm text-ink/80">{review.comment}</p>}
                  <p className="text-[10px] text-muted font-bold mt-1">— {review.reviewer_name || review.client_name || 'Anonymous Client'}</p>
                </>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="text-[10px] text-muted font-medium">Hidden reviews are not visible to clients on your profile.</p>
    </div>
  );
}

// ── DocUploadWidget ────────────────────────────────────────────────────────────
// Handles actual file upload (image, PDF, Word, etc.) or a URL fallback.
// On success calls onUpload(title, serverUrl).
function DocUploadWidget({ onUpload, token }: { onUpload: (title: string, url: string) => void; token: string }) {
  const [title, setTitle] = React.useState('');
  const [file, setFile] = React.useState<File | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [error, setError] = React.useState('');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] || null;
    setFile(f);
    setError('');
    if (f && !title) setTitle(f.name.replace(/\.[^/.]+$/, ''));
  };

  const handleSubmit = async () => {
    if (!title.trim()) { setError('Please enter a document title.'); return; }
    if (!file) { setError('Please choose a file to upload.'); return; }
    setUploading(true); setError('');
    try {
      const formData = new FormData();
      formData.append('title', title.trim());
      formData.append('file', file);
      // token is passed as prop
      const res = await fetch('/api/user/documents/upload', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      if (res.ok) {
        const data = await res.json();
        onUpload(title.trim(), data.file_url);
        setTitle(''); setFile(null);
      } else {
        const d = await res.json().catch(() => ({}));
        setError(d.error || 'Upload failed. Please try again.');
      }
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-3 p-4 bg-paper border-2 border-dashed border-border rounded-2xl">
      <p className="text-xs font-bold uppercase tracking-widest text-muted">Upload New Document</p>
      <input
        type="text"
        placeholder="Document title (e.g. Insurance Certificate)"
        className="input-brutal text-sm"
        value={title}
        onChange={e => setTitle(e.target.value)}
      />
      <label className="block cursor-pointer">
        <div className={`w-full p-3 border-2 border-dashed rounded-xl flex items-center justify-center gap-2 font-bold text-xs transition-all ${file ? 'border-blue-primary bg-blue-light text-blue-primary' : 'border-border hover:border-blue-primary text-muted'}`}>
          <Upload size={15} />
          <span className="truncate">{file ? file.name : 'Choose file (PDF, Word, Image, etc.)'}</span>
        </div>
        <input
          type="file"
          className="hidden"
          accept="image/*,.pdf,.doc,.docx,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
          onChange={handleFileChange}
        />
      </label>
      {file && (
        <p className="text-[10px] text-muted font-medium px-1">
          {file.name} · {(file.size / 1024 / 1024).toFixed(2)} MB
        </p>
      )}
      {error && <p className="text-xs text-red-500 font-bold">{error}</p>}
      <button
        type="button"
        onClick={handleSubmit}
        disabled={uploading || !file || !title.trim()}
        className="btn-primary py-2.5 text-sm w-full flex items-center justify-center gap-2 disabled:opacity-50"
      >
        {uploading ? (
          <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Uploading...</>
        ) : (
          <><Upload size={14} /> Upload Document</>
        )}
      </button>
    </div>
  );
}



interface ProfileProps {
  user: any; profileName: string; setProfileName: (v: string) => void;
  profileBio: string; setProfileBio: (v: string) => void;
  profileAvatar: string; setProfileAvatar: (v: string) => void;
  profileLocation: string; setProfileLocation: (v: string) => void;
  profileSkills: string[]; setProfileSkills: (v: any) => void;
  newSkill: string; setNewSkill: (v: string) => void;
  isSavingProfile: boolean; handleSaveProfile: (e: React.FormEvent) => void;
  setShowDeleteModal: (v: boolean) => void;
  isPublicProfile: boolean; setIsPublicProfile: (v: boolean) => void;
  isPublicDocs: boolean; setIsPublicDocs: (v: boolean) => void;
  handleToggleVisibility: (type: 'profile' | 'docs', value: boolean) => void;
  userDocuments: any[]; handleUploadDocument: (title: string, url: string) => void;
  handleDeleteDocument: (id: string) => void;
  handleDeleteWork: (workId: string) => void;
  handleToggleWorkVisibility: (work: any) => void;
  logout: () => void; setShowWorkModal: (v: boolean) => void;
  token: string | null;
  completedWorks: any[];
}

export default function Profile({ user, profileName, setProfileName, profileBio, setProfileBio, profileAvatar, setProfileAvatar, profileLocation, setProfileLocation, profileSkills, setProfileSkills, newSkill, setNewSkill, isSavingProfile, handleSaveProfile, setShowDeleteModal, isPublicProfile, isPublicDocs, handleToggleVisibility, userDocuments, handleUploadDocument, handleDeleteDocument, handleDeleteWork, handleToggleWorkVisibility, logout, setShowWorkModal, completedWorks, token }: ProfileProps) {
  const [lightboxItem, setLightboxItem] = React.useState<any>(null);

  const getVerificationColor = () => {
    const s = user?.is_verified || 0;
    if (s >= 100) return '#10b981'; if (s >= 50) return '#f59e0b'; return '#ef4444';
  };
  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) { const r = new FileReader(); r.onloadend = () => setProfileAvatar(r.result as string); r.readAsDataURL(file); }
  };
  const ToggleSwitch = ({ checked, onChange }: { checked: boolean; onChange: () => void }) => (
    <button type="button" onClick={onChange} className={`w-12 h-6 rounded-full transition-all relative shrink-0 ${checked ? 'bg-green-500' : 'bg-border'}`}>
      <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all shadow-sm ${checked ? 'left-7' : 'left-1'}`} />
    </button>
  );

  const getMediaType = (work: any) => {
    const url = work.video_url || work.doc_url || work.image_url || '';
    const ft = work.file_type || '';
    if (work.video_url || ft.startsWith('video/') || url.match(/\.(mp4|webm|mov|avi)/i)) return 'video';
    if (work.doc_url || ft === 'application/pdf' || url.match(/\.pdf$/i)) return 'document';
    if (url.match(/\.(jpg|jpeg|png|gif|webp|svg)/i) || url.startsWith('data:image')) return 'image';
    if (url.match(/\.(mp4|webm|mov|avi)/i) || url.startsWith('data:video') || url.startsWith('video:')) return 'video';
    if (url.match(/\.(pdf)/i) || url.startsWith('data:application/pdf')) return 'document';
    if (url.match(/\.(doc|docx)/i) || url.startsWith('doc:') || url.startsWith('data:application')) return 'document';
    return 'document';
  };
  const getItemUrl = (work: any) => work.video_url || work.doc_url || work.image_url || '';

  return (
    <div className="max-w-4xl mx-auto space-y-6 sm:space-y-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-3">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mb-2">My Profile</h1>
          <p className="text-muted font-medium text-sm">Manage your {user?.role === 'client' ? 'account' : 'public presence'}.</p>
        </div>
        {user?.role === 'pro' && (
          <div className={`px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-1.5 border self-start ${user?.is_verified >= 100 ? 'bg-green-light text-green-primary border-green-500/20' : user?.is_verified >= 50 ? 'bg-gold/10 text-gold border-gold/20' : 'bg-red-50 text-red-500 border-red-500/20'}`}>
            {user?.is_verified >= 100 ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}
            {user?.is_verified >= 100 ? 'FULLY VERIFIED' : user?.is_verified >= 50 ? 'PENDING REVIEW' : 'NOT VERIFIED'}
          </div>
        )}
      </div>

      <form onSubmit={handleSaveProfile} className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-10">
        {/* Left Col */}
        <div className="lg:col-span-1 space-y-4 sm:space-y-6">
          <div className="card-brutal p-6 sm:p-8 text-center">
            <div className="relative inline-block mb-5">
              {user?.role === 'pro' && (
                <svg className="absolute -inset-2 w-[calc(100%+16px)] h-[calc(100%+16px)] -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="46" fill="none" stroke={getVerificationColor()} strokeWidth="4" strokeDasharray="100 0" />
                </svg>
              )}
              <div className="relative w-28 h-28 sm:w-32 sm:h-32 rounded-full border-2 border-blue-primary/30 overflow-hidden shadow-[0_4px_20px_#2563eb20] bg-blue-light flex items-center justify-center">
                {profileAvatar ? <img src={profileAvatar} className="w-full h-full object-cover" alt="Avatar" /> : <div className="text-4xl sm:text-5xl font-bold text-blue-primary">{user?.name?.charAt(0)}</div>}
              </div>
              <label className="absolute -bottom-2 -right-2 w-9 h-9 bg-ink text-white rounded-xl flex items-center justify-center border-2 border-white hover:bg-blue-primary transition-all cursor-pointer shadow-md">
                <Upload size={16} /><input type="file" className="hidden" accept="image/*" onChange={handleImageUpload} />
              </label>
            </div>
            <h2 className="text-lg sm:text-xl font-bold mb-1">{user?.name}</h2>
            <p className="text-xs text-muted font-bold uppercase tracking-widest">{user?.role === 'pro' ? 'Specialist' : 'Member'}</p>
          </div>

          {/* FIX #3: Privacy settings - private by default */}
          {user?.role === 'pro' && (
            <div className="card-brutal p-5 sm:p-6 space-y-4">
              <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Privacy Settings</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-paper border border-border rounded-xl gap-3">
                  <div><span className="text-xs font-bold">Public Profile</span><p className="text-[10px] text-muted">Anyone can find you in search</p></div>
                  <ToggleSwitch checked={isPublicProfile} onChange={() => handleToggleVisibility('profile', !isPublicProfile)} />
                </div>
                <div className="flex items-center justify-between p-3 bg-paper border border-border rounded-xl gap-3">
                  <div><span className="text-xs font-bold">Public Documents</span><p className="text-[10px] text-muted">Visible to all users</p></div>
                  <ToggleSwitch checked={isPublicDocs} onChange={() => handleToggleVisibility('docs', !isPublicDocs)} />
                </div>
              </div>
            </div>
          )}

          <div className="card-brutal p-5 sm:p-6 space-y-3">
            <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Account Actions</h3>
            <button type="button" onClick={logout} className="w-full py-3 sm:py-4 bg-red-600 text-white font-black text-base rounded-2xl border border-red-300 shadow-[0_4px_14px_#ef444430] hover:shadow-[0_6px_20px_#ef444440] transition-all flex items-center justify-center gap-2">
              <LogOut size={18} /> Sign Out
            </button>
            <button type="button" onClick={() => setShowDeleteModal(true)} className="w-full py-3 text-xs text-red-500/60 font-medium hover:bg-red-50 rounded-xl transition-all">Delete Account</button>
          </div>
        </div>

        {/* Right Col */}
        <div className="lg:col-span-2 space-y-6">
          <div className="card-brutal p-6 sm:p-8 space-y-5">
            <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Personal Info</h3>
            <div className="space-y-2">
              <label className="block text-xs font-bold uppercase tracking-widest text-muted">Full Name</label>
              <input type="text" className="input-brutal" value={profileName} onChange={e => setProfileName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <label className="block text-xs font-bold uppercase tracking-widest text-muted">Bio</label>
              <textarea className="input-brutal h-28 resize-none" placeholder="Tell clients about yourself..." value={profileBio} onChange={e => setProfileBio(e.target.value)} />
            </div>
            <div className="space-y-2">
              <label className="block text-xs font-bold uppercase tracking-widest text-muted">Location</label>
              <input type="text" className="input-brutal" placeholder="e.g. London, UK" value={profileLocation} onChange={e => setProfileLocation(e.target.value)} />
            </div>
          </div>

          {user?.role === 'pro' && (
            <div className="card-brutal p-6 sm:p-8 space-y-4">
              <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Skills</h3>
              <div className="flex flex-wrap gap-2">
                {profileSkills.map((skill, i) => (
                  <span key={i} className="bg-ink text-white px-3 py-1.5 rounded-xl text-xs font-bold flex items-center gap-1.5">
                    {skill}
                    <button type="button" onClick={() => setProfileSkills((prev: string[]) => prev.filter((_: string, idx: number) => idx !== i))} className="hover:text-red-300 transition-colors"><X size={12} /></button>
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <input type="text" placeholder="Add a skill..." className="input-brutal flex-1 !py-2.5 text-sm" value={newSkill} onChange={e => setNewSkill(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); if (newSkill.trim() && !profileSkills.includes(newSkill.trim())) { setProfileSkills((prev: string[]) => [...prev, newSkill.trim()]); setNewSkill(''); } } }} />
                <button type="button" onClick={() => { if (newSkill.trim() && !profileSkills.includes(newSkill.trim())) { setProfileSkills((prev: string[]) => [...prev, newSkill.trim()]); setNewSkill(''); } }} className="p-3 bg-ink text-white rounded-xl hover:bg-blue-primary transition-all"><Plus size={18} /></button>
              </div>
            </div>
          )}

          <button type="submit" disabled={isSavingProfile} className="w-full btn-primary py-5 text-base font-black disabled:opacity-60">
            {isSavingProfile ? 'Saving...' : 'Save Profile'}
          </button>
        </div>
      </form>

      {/* FIX: Portfolio section — same style as Reviews & Documents */}
      {user?.role === 'pro' && (
        <div className="card-brutal p-6 sm:p-8 space-y-5">
          <div className="flex justify-between items-center flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Portfolio</h3>
              <span className="bg-blue-light text-blue-primary text-[10px] font-bold px-2 py-0.5 rounded-full">Manage visibility</span>
              {completedWorks.length > 0 && (
                <span className="text-[9px] font-bold text-muted bg-paper border border-border px-2 py-1 rounded-full">{completedWorks.length} item{completedWorks.length !== 1 ? 's' : ''}</span>
              )}
            </div>
            <button type="button" onClick={() => setShowWorkModal(true)} className="flex items-center gap-1.5 bg-ink text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-blue-primary transition-all">
              <Plus size={14} /> Add Work
            </button>
          </div>

          {completedWorks.length === 0 ? (
            <div className="p-10 text-center border-2 border-dashed border-border rounded-2xl">
              <div className="text-3xl mb-3">🖼️</div>
              <p className="text-muted font-bold text-sm">No portfolio items yet.</p>
              <p className="text-muted text-xs mt-1">Add images, videos, or documents to showcase your work.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {completedWorks.map((work: any) => {
                const mediaType = getMediaType(work);
                const itemUrl = getItemUrl(work);
                const isHidden = work.is_hidden === true || work.is_hidden === 1;
                return (
                  <div key={work.id} className={`p-4 border-2 rounded-xl transition-all ${isHidden ? 'border-border bg-paper opacity-60' : 'border-green-primary/30 bg-green-light/10'}`}>
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="flex items-center gap-3 min-w-0">
                        {/* Clickable thumbnail */}
                        <div
                          className="w-14 h-14 shrink-0 rounded-xl overflow-hidden border-2 border-border cursor-pointer bg-paper flex items-center justify-center hover:opacity-80 transition-all"
                          onClick={() => setLightboxItem(work)}
                          title="Click to view"
                        >
                          {mediaType === 'image' && itemUrl && (
                            <img src={itemUrl} alt={work.title} className="w-full h-full object-cover" onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                          )}
                          {mediaType === 'video' && (
                            <div className="flex flex-col items-center justify-center w-full h-full bg-blue-light/30">
                              <Play size={18} className="text-blue-primary" />
                              <span className="text-[8px] font-bold text-blue-primary mt-0.5">VIDEO</span>
                            </div>
                          )}
                          {mediaType === 'document' && (
                            <div className="flex flex-col items-center justify-center w-full h-full">
                              <FileText size={18} className="text-muted" />
                              <span className="text-[8px] font-bold text-muted mt-0.5">DOC</span>
                            </div>
                          )}
                          {!itemUrl && <span className="text-[9px] font-bold text-muted text-center p-1 leading-tight">{work.title}</span>}
                        </div>
                        {/* Info */}
                        <div className="min-w-0">
                          <p className="text-sm font-bold truncate">{work.title}</p>
                          {work.description && <p className="text-[11px] text-muted truncate">{work.description}</p>}
                          <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full mt-1 inline-block ${isHidden ? 'bg-border text-muted' : 'bg-green-light text-green-primary'}`}>
                            {isHidden ? 'Hidden' : 'Visible'}
                          </span>
                        </div>
                      </div>
                      {/* Actions — same as reviews */}
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button type="button" onClick={() => setLightboxItem(work)} className="p-1.5 hover:bg-paper rounded-lg transition-all" title="View">
                          <Eye size={14} className="text-blue-primary" />
                        </button>
                        <button type="button" onClick={() => handleToggleWorkVisibility(work)} className="p-1.5 hover:bg-paper rounded-lg transition-all" title={isHidden ? 'Show to clients' : 'Hide from clients'}>
                          {isHidden ? <Eye size={14} className="text-muted" /> : <EyeOff size={14} className="text-green-primary" />}
                        </button>
                        <button type="button" onClick={() => handleDeleteWork(work.id)} className="p-1.5 hover:bg-red-50 rounded-lg transition-all" title="Delete">
                          <Trash2 size={14} className="text-red-400" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <p className="text-[10px] text-muted font-medium">Hidden portfolio items are not visible to clients on your profile.</p>
        </div>
      )}

      {/* Full-size Portfolio Lightbox */}
      {lightboxItem && (
        <div className="fixed inset-0 z-[300] bg-ink/95 flex items-center justify-center p-4" onClick={() => setLightboxItem(null)}>
          <div className="bg-white rounded-2xl overflow-hidden w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-border shrink-0">
              <div>
                <h4 className="font-bold text-base">{lightboxItem.title}</h4>
                {lightboxItem.description && <p className="text-xs text-muted mt-0.5">{lightboxItem.description}</p>}
              </div>
              <div className="flex items-center gap-2">
                {getItemUrl(lightboxItem) && !lightboxItem.video_url && (
                  <a href={getItemUrl(lightboxItem)} target="_blank" rel="noreferrer" download className="flex items-center gap-1 text-xs font-bold text-blue-primary hover:underline px-3 py-2 bg-blue-light rounded-xl">
                    <Download size={14} /> Download
                  </a>
                )}
                <button onClick={() => setLightboxItem(null)} className="p-2 hover:bg-paper rounded-lg"><X size={22} /></button>
              </div>
            </div>
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-paper/50 min-h-[300px]">
              {(() => {
                const url = getItemUrl(lightboxItem);
                const t = getMediaType(lightboxItem);
                const isPdf = t === 'document' && (lightboxItem.file_type === 'application/pdf' || url.endsWith('.pdf'));
                if (t === 'image') return (
                  <img src={url} alt={lightboxItem.title}
                    className="max-w-full max-h-[65vh] object-contain rounded-xl shadow-lg"
                    style={{ width: 'auto', height: 'auto' }}
                  />
                );
                if (t === 'video') return (
                  <video src={url} controls autoPlay className="max-w-full max-h-[65vh] rounded-xl shadow-lg" style={{ width: '100%' }} />
                );
                if (isPdf) return (
                  <iframe src={url} className="w-full rounded-xl" style={{ height: '65vh', minHeight: '400px', border: 'none' }} title={lightboxItem.title} />
                );
                if (t === 'document') return (
                  <div className="flex flex-col items-center justify-center py-12 gap-4">
                    <div className="w-20 h-20 bg-blue-light rounded-2xl flex items-center justify-center">
                      <FileText size={40} className="text-blue-primary" />
                    </div>
                    <p className="font-bold text-lg">{lightboxItem.title}</p>
                    <p className="text-muted text-sm">{lightboxItem.original_name || 'Document file'}</p>
                    <a href={url} target="_blank" rel="noreferrer" download className="btn-primary px-6 py-3 flex items-center gap-2">
                      <Download size={16} /> Download & Open
                    </a>
                  </div>
                );
                return <div className="p-8 text-center text-muted font-bold">No preview available</div>;
              })()}
            </div>
          </div>
        </div>
      )}

      {/* Reviews section — visible to pro only inside their own profile */}
      {user?.role === 'pro' && (
        <ProReviewsManager user={user} token={token} />
      )}

      {/* Documents — pro can see all their own documents including verification docs */}
      {user?.role === 'pro' && (
        <div className="card-brutal p-6 sm:p-8 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <h3 className="font-bold uppercase tracking-widest text-xs text-muted">Documents</h3>
            {userDocuments.length > 0 && (
              <span className="text-[9px] font-bold text-muted bg-paper border border-border px-2 py-1 rounded-full">{userDocuments.length} document{userDocuments.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          {userDocuments.length > 0 ? (
            <div className="space-y-2">
              {/* Show verification docs first */}
              {[...userDocuments.filter((d: any) => d.is_verification_doc), ...userDocuments.filter((d: any) => !d.is_verification_doc)].map((doc: any) => (
                <div key={doc.id} className={`flex items-center justify-between p-3 border rounded-xl ${doc.is_verification_doc ? 'bg-blue-light/20 border-blue-primary/30' : 'bg-paper border-border'}`}>
                  <div className="flex items-center gap-2 min-w-0">
                    <FileText size={14} className={`${doc.is_verification_doc ? 'text-blue-primary' : 'text-muted'} shrink-0`} />
                    <div className="min-w-0">
                      <span className="text-sm font-bold truncate block">{doc.title}</span>
                      {doc.is_verification_doc && (
                        <span className="text-[9px] font-bold text-blue-primary uppercase tracking-wider">Verification Document</span>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0 items-center">
                    <a href={doc.file_url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-xs text-blue-primary font-bold hover:bg-blue-light px-2 py-1 rounded-lg transition-all">
                      <Eye size={11} /> View
                    </a>
                    <button type="button" onClick={() => handleDeleteDocument(doc.id)} className="flex items-center gap-1 text-xs text-red-400 font-bold hover:bg-red-50 px-2 py-1 rounded-lg transition-all">
                      <Trash2 size={11} /> Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted font-medium text-center py-3">No documents uploaded yet.</p>
          )}
          {/* File upload section */}
          <DocUploadWidget onUpload={handleUploadDocument} token={token || ''} />
        </div>
      )}
    </div>
  );
}
