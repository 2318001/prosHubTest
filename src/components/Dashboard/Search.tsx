// FILE: src/components/Dashboard/Search.tsx
// PURPOSE: Search for professionals by skill/keyword. Shows results as cards
//          with "View Profile", "Hire Now" and "Message" actions.
//          Supports local-only filtering.
//
// FIX (post-audit):
//   - Repaired broken JSX in the action buttons block (was causing 10 TS errors)
//   - Added missing `onDirectChat` prop to the interface
//   - "Message" button now correctly wired and only shown for clients

import React from 'react';
import { Search as SearchIcon, MapPin, Star, ArrowRight, ShieldCheck, Briefcase, MessageSquare } from 'lucide-react';
import { motion } from 'motion/react';

interface SearchProps {
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  handleSearch: (e?: React.FormEvent, queryOverride?: string) => void;
  searchResults: any[];
  categories: any[];
  navigate: (path: string) => void;
  onViewProfile: (pro: any) => void;
  onDirectHire?: (pro: any) => void;
  onDirectChat?: (pro: any) => void;
  localOnly: boolean;
  setLocalOnly: (v: boolean) => void;
  userRole?: string;
  hasSearched?: boolean;
}

export default function Search({
  searchQuery, setSearchQuery, handleSearch, searchResults,
  categories, onViewProfile, onDirectHire, onDirectChat,
  localOnly, setLocalOnly, userRole, hasSearched
}: SearchProps) {

  // Show only categories that have actual pros registered — if none yet, show full static fallback
  const catsWithPros = categories.filter(c => c.count > 0);
  const displayCategories = catsWithPros.length > 0 ? categories : [
    { name: 'Plumbing', count: 0 }, { name: 'Electrical', count: 0 }, { name: 'Cleaning', count: 0 },
    { name: 'Handyman', count: 0 }, { name: 'Gardening', count: 0 }, { name: 'IT & Tech', count: 0 },
    { name: 'Painting', count: 0 }, { name: 'Carpentry', count: 0 }, { name: 'Roofing', count: 0 },
    { name: 'Tutoring', count: 0 }, { name: 'Fitness',   count: 0 }, { name: 'Legal',    count: 0 },
    { name: 'Doctor', count: 0 }, { name: 'Dentist', count: 0 }, { name: 'Nursing', count: 0 },
    { name: 'Engineering', count: 0 }, { name: 'Marketing', count: 0 }, { name: 'Photography', count: 0 },
  ];

  return (
    <div className="space-y-8 sm:space-y-10">
      <div>
        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mb-2">Find a Specialist</h1>
        <p className="text-muted font-medium text-sm sm:text-base">Search verified professionals by skill or category.</p>
      </div>

      {/* Search bar */}
      <div className="space-y-3">
        <form onSubmit={e => handleSearch(e)}>
          <div className="relative bg-white border-2 border-blue-primary/30 p-2 rounded-[24px] sm:rounded-[28px] flex items-center gap-2 shadow-[0_4px_20px_#2563eb15] focus-within:shadow-[0_4px_20px_#2563eb40] focus-within:border-blue-primary transition-all">
            <SearchIcon className="ml-3 text-muted shrink-0" size={20} />
            <input
              type="text"
              placeholder="e.g. Plumber, Electrician, Tutor..."
              className="flex-1 bg-transparent border-none outline-none font-bold text-base sm:text-lg p-2 sm:p-3 placeholder:text-muted/40 min-w-0"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
            <button type="submit" className="bg-blue-primary text-white p-3 sm:p-4 rounded-[18px] sm:rounded-[20px] font-bold hover:bg-blue-dark transition-all shadow-lg shrink-0">
              <ArrowRight size={20} />
            </button>
          </div>
        </form>
        <div className="flex items-center gap-3 px-2">
          <button
            onClick={() => setLocalOnly(!localOnly)}
            className={`flex items-center gap-2 px-3 py-2 rounded-xl font-bold text-xs transition-all border-2 ${localOnly ? 'bg-blue-primary text-white border-blue-primary' : 'bg-white text-muted border-border hover:border-blue-primary'}`}
          >
            <MapPin size={13} />{localOnly ? 'Local Only ✓' : 'Filter: Local Only'}
          </button>
        </div>
      </div>

      {/* Category quick-search buttons */}
      <section>
        <h2 className="text-base sm:text-xl font-bold uppercase tracking-widest text-muted mb-4 sm:mb-6">Browse by Category</h2>
        <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2 sm:gap-3">
          {displayCategories.map(cat => (
            <button
              key={cat.name}
              onClick={() => { setSearchQuery(cat.name); handleSearch(undefined, cat.name); }}
              className={`p-3 sm:p-4 bg-white border-2 rounded-xl sm:rounded-2xl hover:border-blue-primary hover:shadow-[0_4px_12px_#2563eb20] transition-all text-center group ${searchQuery === cat.name && hasSearched ? 'border-blue-primary shadow-[3px_3px_0_#2563eb]' : 'border-border'}`}
            >
              <div className="text-[10px] sm:text-xs font-bold uppercase tracking-widest text-muted group-hover:text-ink leading-tight">{cat.name}</div>
              <div className="text-[9px] sm:text-[10px] font-bold text-blue-primary/60 mt-1">{cat.count > 0 ? `${cat.count} Pro${cat.count !== 1 ? 's' : ''}` : 'Tap to search'}</div>
            </button>
          ))}
        </div>
      </section>

      {/* Results — ONLY shown after a search */}
      <section>
        {!hasSearched ? (
          <div className="p-12 sm:p-16 border-4 border-dashed border-border rounded-[32px] sm:rounded-[40px] text-center bg-white/50">
            <div className="text-3xl sm:text-4xl mb-4">✨</div>
            <div className="font-bold text-lg sm:text-xl mb-2">Search for a skill above</div>
            <p className="text-muted font-medium text-sm">Type a skill or tap a category to find matching professionals.</p>
          </div>
        ) : (
          <>
            <h2 className="text-base sm:text-xl font-bold uppercase tracking-widest text-muted mb-4 sm:mb-6">
              {searchResults.length > 0
                ? `${searchResults.length} Specialist${searchResults.length !== 1 ? 's' : ''} matching "${searchQuery}"`
                : `No specialists found for "${searchQuery}"`}
            </h2>

            {searchResults.length === 0 ? (
              <div className="p-12 sm:p-16 border-4 border-dashed border-border rounded-[32px] text-center bg-white/50">
                <div className="text-3xl mb-4">🔍</div>
                <div className="font-bold text-lg mb-2">No matching professionals</div>
                <p className="text-muted text-sm font-medium">Try a different skill, or check that the spelling is correct.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
                {searchResults.map((pro, idx) => (
                  <motion.div
                    key={pro.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.04 }}
                    className="card-brutal p-5 sm:p-8 hover:border-blue-primary group"
                  >
                    <div className="flex items-start gap-4 sm:gap-6 mb-4 sm:mb-6">
                      <div className="relative shrink-0">
                        <div className="w-16 h-16 sm:w-20 sm:h-20 bg-blue-light text-blue-primary rounded-2xl border border-blue-primary/20 flex items-center justify-center text-2xl sm:text-3xl font-bold overflow-hidden">
                          {pro.avatar
                            ? <img src={pro.avatar} className="w-full h-full object-cover" alt={pro.name} onError={e => { (e.target as HTMLImageElement).style.display='none'; }} />
                            : pro.name?.charAt(0)?.toUpperCase()
                          }
                        </div>
                        {pro.is_available === 1 && (
                          <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white rounded-full shadow-[0_0_6px_#22c55e]" title="Available now" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex justify-between items-start gap-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <h3 className="text-lg sm:text-xl font-bold group-hover:text-blue-primary transition-colors truncate">{pro.name}</h3>
                            {pro.is_verified >= 100 && <ShieldCheck size={15} className="text-blue-primary shrink-0" />}
                          </div>
                          <div className="flex items-center gap-1 bg-gold/10 text-gold px-2 py-1 rounded-lg text-[10px] font-bold shrink-0">
                            {pro.avg_rating
                              ? <><Star size={11} fill="currentColor" /> {pro.avg_rating}</>
                              : <span className="text-muted/60">New</span>
                            }
                          </div>
                        </div>
                        <div className="flex items-center gap-1 text-muted font-bold text-xs mt-1">
                          <MapPin size={12} className="shrink-0" />
                          <span className="truncate">
                            {pro.distance != null ? `${Math.round(pro.distance)} km away` : (pro.location || 'Remote')}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {(pro.skills || []).slice(0, 3).map((s: string, i: number) => (
                            <span key={i} className="bg-paper border border-border px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider text-muted">{s}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <p className="text-muted font-medium text-xs sm:text-sm mb-4 sm:mb-5 line-clamp-2">{pro.bio || 'No bio provided.'}</p>

                    {/* Action buttons — View Profile + Hire Now + Message */}
                    <div className="flex flex-wrap gap-2 sm:gap-3 pt-3 sm:pt-4 border-t border-border">
                      <button
                        onClick={() => onViewProfile(pro)}
                        className="flex-1 min-w-[100px] btn-secondary py-3 text-sm"
                      >
                        View Profile
                      </button>
                      {userRole === 'client' && onDirectHire && (
                        <button
                          onClick={() => onDirectHire(pro)}
                          className="flex-1 min-w-[100px] btn-primary py-3 text-sm flex items-center justify-center gap-1.5"
                        >
                          <Briefcase size={14} /> Hire Now
                        </button>
                      )}
                      {userRole === 'client' && onDirectChat && (
                        <button
                          onClick={() => onDirectChat(pro)}
                          className="flex-1 min-w-[100px] py-3 text-sm font-bold rounded-xl border-2 border-border text-muted hover:border-blue-primary hover:text-blue-primary bg-white transition-all flex items-center justify-center gap-1.5"
                        >
                          <MessageSquare size={14} /> Message
                        </button>
                      )}
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
