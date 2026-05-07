// FILE: src/components/Dashboard/ProProfileModal.tsx — Full pro profile modal, mobile-first.

import React from 'react';
import { X, MapPin, ShieldCheck, Star, Briefcase, MessageSquare, UserCheck, Clock, Play, FileText, Download, Eye } from 'lucide-react';
import { motion } from 'motion/react';

function getMediaType(item: any) {
  const url = item.video_url || item.doc_url || item.image_url || '';
  const ft = item.file_type || '';
  if (item.video_url || ft.startsWith('video/') || url.match(/\.(mp4|webm|mov|avi)/i)) return 'video';
  if (item.doc_url || ft === 'application/pdf' || url.match(/\.pdf$/i)) return 'pdf';
  if (url.match(/\.(jpg|jpeg|png|gif|webp|svg)/i) || url.startsWith('data:image')) return 'image';
  if (url.match(/\.(mp4|webm|mov|avi)/i) || url.startsWith('data:video') || url.startsWith('video:')) return 'video';
  if (url.match(/\.pdf$/i) || url.startsWith('data:application/pdf')) return 'pdf';
  return 'document';
}

function getItemUrl(item: any) {
  return item.video_url || item.doc_url || item.image_url || '';
}

function PortfolioGrid({ items }: { items: any[] }) {
  const [lightbox, setLightbox] = React.useState<any>(null);

  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {items.map((p: any) => {
          const mt = getMediaType(p);
          const url = getItemUrl(p);
          return (
            <div key={p.id} className="relative group cursor-pointer" onClick={() => setLightbox(p)}>
              <div className="aspect-video bg-paper border-2 border-border rounded-xl overflow-hidden">
                {mt === 'image' && (
                  <img src={url} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200" alt={p.title} onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                )}
                {mt === 'video' && (
                  <div className="w-full h-full flex flex-col items-center justify-center bg-ink/5">
                    <Play size={28} className="text-blue-primary mb-1" />
                    <span className="text-[9px] font-bold text-muted uppercase">Video</span>
                  </div>
                )}
                {(mt === 'pdf' || mt === 'document') && (
                  <div className="w-full h-full flex flex-col items-center justify-center bg-paper">
                    <FileText size={28} className="text-muted mb-1" />
                    <span className="text-[9px] font-bold text-muted uppercase">{mt === 'pdf' ? 'PDF' : 'Document'}</span>
                  </div>
                )}
                {!url && (
                  <div className="w-full h-full flex items-center justify-center p-2">
                    <span className="text-xs font-bold text-muted text-center">{p.title}</span>
                  </div>
                )}
              </div>
              <div className="absolute inset-0 bg-ink/60 opacity-0 group-hover:opacity-100 transition-opacity rounded-xl flex items-center justify-center">
                <Eye size={22} className="text-white" />
              </div>
              <p className="text-[10px] font-bold truncate mt-1 px-0.5">{p.title}</p>
            </div>
          );
        })}
      </div>

      {/* Full-size lightbox */}
      {lightbox && (
        <div className="fixed inset-0 z-[400] bg-ink/95 flex items-center justify-center p-4" onClick={() => setLightbox(null)}>
          <div className="bg-white rounded-2xl overflow-hidden w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-border shrink-0">
              <div>
                <h4 className="font-bold">{lightbox.title}</h4>
                {lightbox.description && <p className="text-xs text-muted mt-0.5">{lightbox.description}</p>}
              </div>
              <div className="flex items-center gap-2">
                {getItemUrl(lightbox) && (
                  <a href={getItemUrl(lightbox)} download target="_blank" rel="noreferrer"
                    className="flex items-center gap-1 text-xs font-bold text-blue-primary px-3 py-2 bg-blue-light rounded-xl hover:bg-blue-primary hover:text-white transition-all">
                    <Download size={13} /> Download
                  </a>
                )}
                <button onClick={() => setLightbox(null)} className="p-2 hover:bg-paper rounded-lg"><X size={20} /></button>
              </div>
            </div>
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-paper/50 min-h-[280px]">
              {(() => {
                const url = getItemUrl(lightbox);
                const mt = getMediaType(lightbox);
                if (mt === 'image') return (
                  <img src={url} alt={lightbox.title} className="max-w-full max-h-[65vh] object-contain rounded-xl shadow-lg" />
                );
                if (mt === 'video') return (
                  <video src={url} controls autoPlay className="max-w-full max-h-[65vh] rounded-xl w-full" />
                );
                if (mt === 'pdf') return (
                  <iframe src={url} className="w-full rounded-xl" style={{ height: '65vh', minHeight: '400px', border: 'none' }} title={lightbox.title} />
                );
                return (
                  <div className="flex flex-col items-center gap-4 py-10">
                    <div className="w-20 h-20 bg-blue-light rounded-2xl flex items-center justify-center">
                      <FileText size={40} className="text-blue-primary" />
                    </div>
                    <p className="font-bold">{lightbox.title}</p>
                    <a href={url} download target="_blank" rel="noreferrer" className="btn-primary px-6 py-3 flex items-center gap-2">
                      <Download size={16} /> Download File
                    </a>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      )}
    </>
  );
}



interface ProProfileModalProps {
  pro: any;
  onClose: () => void;
  onHire: (pro: any) => void;
  onChat: (pro: any) => void;
  userRole?: string;
}

export default function ProProfileModal({ pro, onClose, onHire, onChat, userRole }: ProProfileModalProps) {
  if (!pro) return null;

  const avgRating = pro.reviews?.length
    ? (pro.reviews.reduce((sum: number, r: any) => sum + (r.rating || 0), 0) / pro.reviews.length).toFixed(1)
    : null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[200] flex items-end sm:items-center justify-center p-0 sm:p-4"
    >
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-ink/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div
        initial={{ y: '100%', opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: '100%', opacity: 0 }}
        transition={{ type: 'spring', damping: 30, stiffness: 300 }}
        className="relative bg-white border-t border-blue-primary/20 sm:border sm:border-blue-primary/20 rounded-t-[32px] sm:rounded-[32px] shadow-2xl w-full sm:max-w-3xl max-h-[92vh] sm:max-h-[85vh] overflow-y-auto"
      >
        {/* Drag handle */}
        <div className="w-12 h-1.5 bg-border rounded-full mx-auto mt-3 mb-1 sm:hidden sticky top-3" />

        {/* Close */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 sm:top-6 sm:right-6 p-2 hover:bg-paper rounded-xl transition-all z-10"
        >
          <X size={22} />
        </button>

        {/* Header */}
        <div className="p-5 sm:p-8 border-b border-blue-primary/20 bg-paper">
          <div className="flex items-start gap-4 sm:gap-6">
            <div className="relative shrink-0">
              <div className="w-16 h-16 sm:w-20 sm:h-20 bg-blue-light text-blue-primary rounded-2xl border border-blue-primary/20 flex items-center justify-center text-2xl sm:text-3xl font-black">
                {pro.avatar
                  ? <img src={pro.avatar} className="w-full h-full rounded-2xl object-cover" alt={pro.name} />
                  : pro.name?.charAt(0)}
              </div>
              {pro.is_available === 1 && (
                <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white rounded-full shadow-[0_0_8px_#22c55e]" />
              )}
            </div>
            <div className="flex-1 min-w-0 pr-8">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <h2 className="text-xl sm:text-3xl font-black truncate">{pro.name}</h2>
                {pro.is_verified >= 100 && (
                  <div className="text-blue-primary" title="Identity Verified"><ShieldCheck size={18} fill="currentColor" fillOpacity={0.1} /></div>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-xs sm:text-sm font-bold text-muted">
                {pro.location && <div className="flex items-center gap-1"><MapPin size={13} /> {pro.location}</div>}
                {avgRating && (
                  <div className="flex items-center gap-1 text-gold"><Star size={13} fill="currentColor" /> {avgRating} ({pro.reviews?.length} reviews)</div>
                )}
                <div className={`flex items-center gap-1 ${pro.is_available === 1 ? 'text-green-primary' : 'text-muted'}`}>
                  <div className={`w-2 h-2 rounded-full ${pro.is_available === 1 ? 'bg-green-500' : 'bg-border'}`} />
                  {pro.is_available === 1 ? 'Available' : 'Unavailable'}
                </div>
              </div>
              {/* Skills */}
              <div className="flex flex-wrap gap-1.5 mt-3">
                {(pro.skills || []).slice(0, 5).map((s: string, i: number) => (
                  <span key={i} className="bg-ink text-white px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider">{s}</span>
                ))}
                {(pro.skills || []).length > 5 && (
                  <span className="bg-paper border border-border px-2.5 py-1 rounded-lg text-[10px] font-bold text-muted">+{pro.skills.length - 5} more</span>
                )}
              </div>
            </div>
          </div>

          {/* CTA Buttons — always show both Hire and Chat (not just one on mobile) */}
          <div className="flex gap-3 mt-5">
            {userRole === 'client' && (
              <button onClick={() => onHire(pro)} className="flex-1 btn-primary py-3 flex items-center justify-center gap-2 text-sm sm:text-base">
                <Briefcase size={16} /> Hire Now
              </button>
            )}
            <button onClick={() => onChat(pro)} className={`flex-1 ${userRole === 'client' ? 'btn-secondary' : 'btn-primary'} py-3 flex items-center justify-center gap-2 text-sm sm:text-base`}>
              <MessageSquare size={16} /> Message
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 sm:p-8 space-y-6 sm:space-y-8">
          {/* Bio */}
          {pro.bio && (
            <section>
              <h3 className="text-xs font-black uppercase tracking-widest text-muted mb-3 flex items-center gap-2"><UserCheck size={14} /> About</h3>
              <p className="text-sm sm:text-base font-medium text-ink/80 leading-relaxed">{pro.bio}</p>
            </section>
          )}

          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'Jobs Done', val: pro.work_history?.length ?? 0, color: 'bg-green-light text-green-primary' },
              { label: 'Reviews', val: pro.reviews?.length ?? 0, color: 'bg-gold/10 text-gold' },
              { label: 'Portfolio', val: pro.portfolio?.length ?? 0, color: 'bg-blue-light text-blue-primary' },
            ].map(s => (
              <div key={s.label} className={`${s.color} p-3 sm:p-4 rounded-2xl text-center`}>
                <div className="text-2xl sm:text-3xl font-black">{s.val}</div>
                <div className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Portfolio — only show non-hidden items to public */}
          {pro.portfolio?.filter((p: any) => !p.is_hidden && p.is_hidden !== 1).length > 0 && (
            <section>
              <h3 className="text-xs font-black uppercase tracking-widest text-muted mb-3 flex items-center gap-2"><Briefcase size={14} /> Portfolio</h3>
              <PortfolioGrid items={pro.portfolio.filter((p: any) => !p.is_hidden && p.is_hidden !== 1)} />
            </section>
          )}

          {/* Reviews — only show public ones to clients */}
          {pro.reviews?.filter((r: any) => !r.is_private).length > 0 && (
            <section>
              <h3 className="text-xs font-black uppercase tracking-widest text-muted mb-3 flex items-center gap-2"><Star size={14} /> Reviews</h3>
              <div className="space-y-3">
                {pro.reviews.filter((r: any) => !r.is_private).slice(0, 3).map((r: any) => (
                  <div key={r.id} className="p-4 bg-paper border-2 border-border rounded-2xl">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-1">
                        {[1,2,3,4,5].map(s => (
                          <Star key={s} size={13} className={s <= r.rating ? 'text-gold' : 'text-border'} fill={s <= r.rating ? 'currentColor' : 'none'} />
                        ))}
                      </div>
                      <div className="text-[10px] font-bold text-muted flex items-center gap-1">
                        <Clock size={11} /> {new Date(r.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    {r.comment && <p className="text-xs sm:text-sm font-medium text-ink/70">{r.comment}</p>}
                    <div className="text-[10px] font-bold text-muted mt-2">— {r.client_name || 'Anonymous'}</div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
