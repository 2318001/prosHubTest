// FILE: src/components/Dashboard/Sidebar.tsx — Responsive sidebar navigation.

import React from 'react';
import { Plus, Clock, Briefcase, Search, UserCheck, ShieldCheck, Bell, LogOut, Menu, X, Home, Zap, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';

interface SidebarProps {
  view: string;
  setView: (view: any) => void;
  user: any;
  logout: () => void;
  isSidebarOpen: boolean;
  setIsSidebarOpen: (open: boolean) => void;
  notificationsCount: number;
  isAvailable?: boolean;
  onToggleAvailability?: () => void;
  onShowSubscription?: () => void;
}

export default function Sidebar({
  view, setView, user, logout, isSidebarOpen, setIsSidebarOpen,
  notificationsCount, isAvailable, onToggleAvailability, onShowSubscription
}: SidebarProps) {
  const navItem = (id: string, icon: React.ReactNode, label: string, badge?: number) => (
    <button
      onClick={() => { setView(id); setIsSidebarOpen(false); }}
      className={`w-full flex items-center justify-between p-3 rounded-xl font-bold transition-all text-left ${view === id ? 'bg-blue-primary text-white' : 'text-white/60 hover:bg-white/5 hover:text-white'}`}
    >
      <div className="flex items-center gap-3">
        {icon}
        <span className="text-sm">{label}</span>
      </div>
      {badge && badge > 0 && (
        <span className="bg-red-500 text-white text-[10px] px-2 py-0.5 rounded-full font-bold">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="p-5 text-2xl font-bold tracking-tighter border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-primary text-white flex items-center justify-center rounded-lg text-lg font-bold shrink-0">P</div>
          <span>Pros<span className="text-blue-primary">Hub</span></span>
        </div>
        <button onClick={() => setIsSidebarOpen(false)} className="lg:hidden p-1 hover:bg-white/10 rounded-lg">
          <X size={22} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <Link to="/" className="w-full flex items-center gap-3 p-3 rounded-xl font-bold transition-all text-white/50 hover:bg-white/5 hover:text-white text-sm">
          <Home size={18} /> Home Page
        </Link>
        {navItem('overview', <Briefcase size={18} />, 'Overview')}
        {navItem('jobs', <Clock size={18} />, 'My Jobs')}
        {navItem('search', <Search size={18} />, 'Find Pros')}
        {navItem('notifications', <Bell size={18} />, 'Notifications', notificationsCount)}
        {user?.role === 'pro' && navItem('verification', <ShieldCheck size={18} />, 'Verification')}
        {navItem('profile', <UserCheck size={18} />, 'My Profile')}
        {user?.role === 'pro' && (
          <button
            onClick={() => { onShowSubscription?.(); setIsSidebarOpen(false); }}
            className="w-full flex items-center gap-3 p-3 rounded-xl font-bold transition-all text-gold hover:bg-gold/10 text-sm"
          >
            <Zap size={18} /> Subscription
          </button>
        )}
        {user?.is_admin === 1 && navItem('admin', <ShieldAlert size={18} />, 'Admin Panel')}
      </nav>

      {/* Bottom */}
      <div className="p-3 border-t border-white/5 space-y-3 safe-bottom">
        {user?.role === 'pro' && (
          <div className={`p-3 rounded-2xl border-2 transition-all duration-300 flex items-center justify-between ${isAvailable ? 'bg-green-500/10 border-green-500/50' : 'bg-white/5 border-white/10'}`}>
            <div className="flex items-center gap-2.5">
              <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${isAvailable ? 'bg-green-500 shadow-[0_0_10px_#22c55e]' : 'bg-white/20'}`} />
              <div className="flex flex-col">
                <span className="text-[9px] font-bold uppercase tracking-widest text-white/40">Status</span>
                <span className={`text-xs font-black uppercase tracking-widest ${isAvailable ? 'text-green-500' : 'text-white/60'}`}>
                  {isAvailable ? 'Online' : 'Offline'}
                </span>
              </div>
            </div>
            <button
              onClick={onToggleAvailability}
              className={`w-11 h-6 rounded-full relative transition-all duration-300 border border-white/20 shrink-0 ${isAvailable ? 'bg-green-500' : 'bg-white/10'}`}
            >
              <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all duration-300 shadow-sm ${isAvailable ? 'left-6' : 'left-0.5'}`} />
            </button>
          </div>
        )}

        <div className="flex items-center gap-3 p-2 bg-white/5 rounded-2xl border border-white/10">
          <img
            src={user?.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user?.name || 'U')}&background=2563eb&color=fff`}
            alt={user?.name}
            className="w-9 h-9 rounded-xl object-cover border border-white/10 shrink-0"
            onError={(e: any) => { e.target.src = `https://ui-avatars.com/api/?name=U&background=2563eb&color=fff`; }}
          />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-bold truncate text-white">{user?.name}</div>
            <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest">
              {user?.role === 'pro' ? 'Pro Specialist' : 'Client'}
            </div>
          </div>
        </div>

        <button
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 p-3 rounded-2xl font-black text-white bg-red-600 border border-red-300 shadow-[0_4px_14px_#ef444430] hover:shadow-[0_6px_20px_#ef444440] transition-all text-sm"
        >
          <LogOut size={18} /> Sign Out
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Top Bar */}
      <div className="lg:hidden bg-ink text-white px-4 py-3 flex justify-between items-center sticky top-0 z-30 border-b border-white/10 safe-top">
        <div className="text-xl font-bold tracking-tighter flex items-center gap-2">
          <div className="w-7 h-7 bg-blue-primary text-white flex items-center justify-center rounded-lg text-base font-bold">P</div>
          Pros<span className="text-blue-primary">Hub</span>
        </div>
        <div className="flex items-center gap-3">
          {notificationsCount > 0 && (
            <button onClick={() => { setView('notifications'); setIsSidebarOpen(false); }} className="relative">
              <Bell size={22} className="text-white/70" />
              <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[9px] w-4 h-4 rounded-full flex items-center justify-center font-bold">
                {notificationsCount > 9 ? '9+' : notificationsCount}
              </span>
            </button>
          )}
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="p-2 hover:bg-white/10 rounded-lg transition-all">
            {isSidebarOpen ? <X size={22} /> : <Menu size={22} />}
          </button>
        </div>
      </div>

      {/* Mobile Overlay */}
      <AnimatePresence>
        {isSidebarOpen && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-ink/50 z-40 lg:hidden"
            onClick={() => setIsSidebarOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 w-64 bg-ink text-white z-50 transition-transform duration-300
        ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        lg:translate-x-0 lg:static lg:h-screen
      `}>
        {sidebarContent}
      </aside>
    </>
  );
}
