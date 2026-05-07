// FILE: src/Landing.tsx — Public marketing landing page. Hero search redirects to /login?search=... for guests. Fetches live category stats on mount.

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';
// Lucide-react provides the icons like Search, Zap, etc.
import { 
  Zap, Search, ArrowRight, ArrowRightLeft, UserCheck, Globe, 
  Wrench, Scale, Dumbbell, TrendingUp, Code, Briefcase,
  X, MousePointer2, MessageSquare, ShieldCheck, CreditCard,
  Twitter, Github, Linkedin, Instagram, Star, Clock, Menu, ChevronDown, ChevronUp
} from 'lucide-react';
// Motion is used for smooth entrance animations
import { motion, AnimatePresence } from 'motion/react';

/**
 * ENHANCED LANDING PAGE
 * Clean, modern, and focused on the core search action with category quick-links.
 * Includes floating visual elements to make the page feel alive and interactive.
 */
export default function Landing() {
  // --- JAVASCRIPT LOGIC ---
  const { isAuthenticated } = useAuth();
  const [searchQuery, setSearchQuery] = useState(''); // Stores what the user types in the search box
  const [showHowModal, setShowHowModal] = useState(false); // Controls "How it Works" modal
  const [showServicesModal, setShowServicesModal] = useState(false); // Controls "Services" modal
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false); // Controls mobile hamburger menu
  const [catStats, setCatStats] = useState<{name: string, count: number}[]>([]); // Stores pro counts per category
  const navigate = useNavigate(); // Used to redirect the user to the login/dashboard page

  // Prevent body scroll when mobile menu is open
  React.useEffect(() => {
    if (isMobileMenuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isMobileMenuOpen]);

  // Fetch stats on load
  React.useEffect(() => {
    fetch('/api/stats/categories')
      .then(res => res.ok ? res.json() : [])
      .then(data => { if (Array.isArray(data)) setCatStats(data); })
      .catch(() => {});
  }, []);

  /**
   * HANDLE SEARCH
   * When the user clicks the search button, we take them to the login page
   * and pass their search query so they don't have to type it again.
   */
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (isAuthenticated) {
      navigate(`/dashboard?search=${searchQuery}`);
    } else {
      navigate(`/login?search=${searchQuery}`);
    }
  };

  // Default icons for known categories
  const getIcon = (name: string) => {
    const n = name.toLowerCase();
    if (n.includes('plumb')) return <Wrench size={24} className="text-blue-500" />;
    if (n.includes('electr')) return <Zap size={24} className="text-yellow-500" />;
    if (n.includes('clean')) return <ShieldCheck size={24} className="text-emerald-500" />;
    if (n.includes('handy')) return <Briefcase size={24} className="text-orange-500" />;
    if (n.includes('garden')) return <TrendingUp size={24} className="text-green-500" />;
    if (n.includes('it') || n.includes('tech') || n.includes('code')) return <Code size={24} className="text-purple-500" />;
    if (n.includes('legal') || n.includes('law')) return <Scale size={24} className="text-slate-500" />;
    if (n.includes('fit') || n.includes('gym') || n.includes('train')) return <Dumbbell size={24} className="text-red-500" />;
    if (n.includes('market') || n.includes('seo')) return <TrendingUp size={24} className="text-emerald-500" />;
    if (n.includes('write') || n.includes('edit')) return <Briefcase size={24} className="text-orange-500" />;
    if (n.includes('photo')) return <Globe size={24} className="text-pink-500" />;
    return <Globe size={24} className="text-indigo-500" />;
  };

  // Categories to display on the main page (Top 6 from DB or defaults)
  const displayCategories = catStats.length > 0 
    ? catStats.slice(0, 6) 
    : [
        { name: 'Plumbing', count: 0 },
        { name: 'Electrical', count: 0 },
        { name: 'Cleaning', count: 0 },
        { name: 'Handyman', count: 0 },
        { name: 'Gardening', count: 0 },
        { name: 'IT & Tech', count: 0 }
      ];

  // Extended services for the modal (Top 12 from DB or defaults)
  const allServices = catStats.length > 0
    ? catStats
    : [
        ...displayCategories,
        { name: 'Writing', count: 0 },
        { name: 'Photography', count: 0 },
        { name: 'Tutoring', count: 0 },
      ];

  // How it works steps (5 total: Search → Negotiate → Hire → Verified → Review)
  const steps = [
    { title: 'Search', desc: 'Find any micro-skill or service instantly using our smart search engine.', icon: <Search className="text-blue-primary" /> },
    { title: 'Negotiate', desc: 'Chat directly with verified pros and agree on a fair price that works for both sides.', icon: <MessageSquare className="text-gold" /> },
    { title: 'Hire', desc: 'Confirm the match and get started. Both parties confirm before work begins.', icon: <Briefcase className="text-green-primary" /> },
    { title: 'Verified', desc: 'Every pro is identity-checked for your complete peace of mind.', icon: <ShieldCheck className="text-blue-primary" /> },
    // Step 5 — Review: closes the trust loop so clients can rate the work and pros build reputation
    { title: 'Review', desc: 'After the job is done, leave a review. Your feedback helps the whole community find the best pros.', icon: <Star className="text-gold" /> },
  ];

  // --- HTML STRUCTURE (JSX) & CSS (Tailwind) ---
  return (
    <div
      className="min-h-screen w-full flex flex-col selection:bg-blue-primary selection:text-white relative overflow-x-hidden"
      style={{
       // backgroundImage: 'url(/PP.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        backgroundAttachment: 'fixed',
      }}
    >
      {/* White overlay so text stays readable over the background image.
          Adjust opacity: bg-white/50 = more image visible, bg-white/85 = less image visible */}
      <div className="absolute inset-0 bg-white/70 -z-10 pointer-events-none" />

      {/* BACKGROUND DECORATION: Floating blur circles to add depth */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-blue-primary/5 rounded-full blur-[120px] -z-10 animate-pulse"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-gold/5 rounded-full blur-[150px] -z-10"></div>
      <div className="absolute top-[20%] right-[5%] w-[20%] h-[20%] bg-green-primary/5 rounded-full blur-[100px] -z-10"></div>
      
      {/* NAVIGATION: The top bar with the logo and links */}
      <nav className="w-full sticky top-0 z-50 bg-white/70 backdrop-blur-md border-b border-transparent transition-all">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          {/* Logo Section */}
          <div className="text-2xl font-bold tracking-tighter flex items-center gap-2 cursor-pointer" onClick={() => navigate('/')}>
            <div className="w-8 h-8 bg-ink text-white flex items-center justify-center rounded-lg text-lg font-bold">P</div>
            Pros<span className="text-blue-primary">Hub</span>
          </div>

          {/* Center Links */}
          <div className="hidden md:flex items-center gap-10 text-sm font-bold text-muted">
            <button onClick={() => setShowHowModal(true)} className="hover:text-ink transition-colors relative group">
              How it works
              <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-blue-primary transition-all group-hover:w-full"></span>
            </button>
            <button onClick={() => setShowServicesModal(true)} className="hover:text-ink transition-colors relative group">
              Services
              <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-blue-primary transition-all group-hover:w-full"></span>
            </button>
          </div>
          
          {/* Action Buttons */}
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-8">
              {isAuthenticated ? (
                <Link to="/dashboard" className="bg-ink text-white px-6 py-2.5 rounded-2xl font-bold hover:bg-blue-primary transition-all shadow-xl hover:shadow-blue-primary/20 text-sm">Dashboard</Link>
              ) : (
                <>
                  <Link to="/login" className="font-bold text-muted hover:text-ink transition-colors text-sm">Log In</Link>
                  <Link to="/login" className="bg-ink text-white px-6 py-2.5 rounded-2xl font-bold hover:bg-blue-primary transition-all shadow-xl hover:shadow-blue-primary/20 text-sm">Join Now</Link>
                </>
              )}
            </div>
            
            {/* Mobile Menu Toggle */}
            <button 
              onClick={() => setIsMobileMenuOpen(true)}
              className="md:hidden p-2 bg-white border border-blue-primary/30 rounded-xl shadow-[0_2px_8px_#2563eb20] active:shadow-none transition-all"
            >
              <Menu size={24} />
            </button>
          </div>
        </div>
      </nav>

      {/* MOBILE MENU OVERLAY */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div 
            initial={{ opacity: 0, x: '100%' }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: '100%' }}
            className="fixed inset-0 z-[100] bg-white p-8 flex flex-col overflow-y-auto"
          >
            <div className="flex justify-between items-center mb-12">
              <div className="text-2xl font-bold tracking-tighter flex items-center gap-2">
                <div className="w-8 h-8 bg-ink text-white flex items-center justify-center rounded-lg text-lg font-bold">P</div>
                Pros<span className="text-blue-primary">Hub</span>
              </div>
              <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 hover:bg-paper rounded-full transition-all">
                <X size={28} />
              </button>
            </div>

            <div className="flex flex-col gap-6">
              <div className="text-xs font-black uppercase tracking-[0.2em] text-muted/60 mb-2">Navigation</div>
              <button 
                onClick={() => { setShowHowModal(true); setIsMobileMenuOpen(false); }}
                className="text-2xl font-black text-left hover:text-blue-primary transition-colors"
              >
                How it works
              </button>
              <button 
                onClick={() => { setShowServicesModal(true); setIsMobileMenuOpen(false); }}
                className="text-2xl font-black text-left hover:text-blue-primary transition-colors"
              >
                Services
              </button>
              
              <div className="text-xs font-black uppercase tracking-[0.2em] text-muted/60 mt-4 mb-2">Quick Jump</div>
              <button 
                onClick={() => { document.getElementById('categories')?.scrollIntoView({ behavior: 'smooth' }); setIsMobileMenuOpen(false); }}
                className="text-2xl font-black text-left hover:text-blue-primary transition-colors"
              >
                Pro Categories
              </button>
              <button 
                onClick={() => { document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' }); setIsMobileMenuOpen(false); }}
                className="text-2xl font-black text-left hover:text-blue-primary transition-colors"
              >
                Our Features
              </button>

              <div className="h-px bg-border my-4"></div>
              {isAuthenticated ? <Link to="/dashboard" className="text-2xl font-black text-left hover:text-blue-primary transition-colors">Dashboard</Link> : <Link to="/login" className="text-2xl font-black text-left hover:text-blue-primary transition-colors">Log In</Link>}
              {!isAuthenticated && <Link to="/login" className="bg-ink text-white p-5 rounded-[24px] font-black text-xl text-center shadow-[8px_8px_0_#3B82F6]">Join Now</Link>}
            </div>

            <div className="mt-auto pt-12 text-center text-muted font-bold text-sm">
              © 2026 ProsHub. All Rights Reserved.
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* CENTERED HERO CONTENT */}
      <main className="flex-1 flex flex-col items-center justify-start pt-10 sm:pt-20 md:pt-32 px-4 sm:px-6 pb-12 relative overflow-hidden md:overflow-visible">
        
        {/* Animated Content Wrapper */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="w-full max-w-5xl text-center z-10"
        >
          {/* Badge */}
          <div className="inline-flex items-center gap-2 bg-blue-light text-blue-primary px-4 py-2 rounded-full font-bold text-[10px] mb-6 uppercase tracking-[0.2em]">
            <Zap size={14} className="animate-pulse" />
            The Professional Skills Hub
          </div>

          {/* Headline: Reduced size to keep search bar visible */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-semibold tracking-tight leading-[1] mb-6">
            Find Any <span className="text-blue-primary italic">Skill</span> <br className="hidden md:block" />
            In <span className="underline decoration-blue-primary/30 decoration-[8px] underline-offset-[8px]">Seconds.</span>
          </h1>

          {/* Subheadline */}
          <p className="text-base sm:text-lg text-muted mb-8 max-w-2xl mx-auto leading-relaxed font-medium px-4 md:px-0">
            The world's first skills hub. Search for any micro-skill, negotiate your price, and hire verified pros instantly. Physical or remote.
          </p>

          {/* Search Bar Form */}
          <form onSubmit={handleSearch} className="relative group mb-16 md:mb-24 max-w-2xl mx-auto">
            <div className="relative bg-white border-2 border-blue-primary/30 p-2 rounded-[28px] flex items-center gap-2 shadow-[0_8px_30px_#2563eb20] group-focus-within:shadow-[0_8px_30px_#2563eb50] transition-all">
              <Search className="ml-4 text-muted" size={24} />
              <input 
                type="text" 
                placeholder="What skill do you need?"
                className="flex-1 bg-transparent border-none outline-none font-bold text-lg p-3 placeholder:text-muted/40"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
              <button type="submit" className="bg-blue-primary text-white p-4 rounded-[20px] font-bold hover:bg-blue-dark transition-all shadow-lg">
                <ArrowRight size={24} />
              </button>
            </div>
          </form>
        </motion.div>
      </main>

      {/* DESIGNED FOOTER */}
      <footer className="w-full px-8 py-12 bg-white border-t border-border z-10" id="features">
        <div className="max-w-7xl mx-auto">
          {/* Complex Footer - Desktop Only */}
          <div className="hidden md:block">
            {/* Trust Badges Section */}
            <div className="grid grid-cols-4 gap-8 mb-16 pb-16 border-b border-border">
              <div className="flex flex-col items-center text-center gap-3">
                <div className="w-12 h-12 bg-green-light rounded-2xl flex items-center justify-center text-green-primary">
                  <ShieldCheck size={24} />
                </div>
                <div className="font-black uppercase tracking-widest text-[10px]">100% Verified</div>
                <p className="text-[10px] font-medium text-muted">Every specialist is identity checked</p>
              </div>
              <div className="flex flex-col items-center text-center gap-3">
                <div className="w-12 h-12 bg-green-light rounded-2xl flex items-center justify-center text-green-primary">
                  <MessageSquare size={24} />
                </div>
                <div className="font-black uppercase tracking-widest text-[10px]">Direct Chat</div>
                <p className="text-[10px] font-medium text-muted">Negotiate directly with specialists</p>
              </div>
              <div className="flex flex-col items-center text-center gap-3">
                <div className="w-12 h-12 bg-gold/10 rounded-2xl flex items-center justify-center text-gold">
                  <Star size={24} />
                </div>
                <div className="font-black uppercase tracking-widest text-[10px]">Top Rated Pros</div>
                <p className="text-[10px] font-medium text-muted">Only the best specialists allowed</p>
              </div>
              <div className="flex flex-col items-center text-center gap-3">
                <div className="w-12 h-12 bg-ink/5 rounded-2xl flex items-center justify-center text-ink">
                  <Clock size={24} />
                </div>
                <div className="font-black uppercase tracking-widest text-[10px]">Instant Hire</div>
                <p className="text-[10px] font-medium text-muted">Find help in under 60 seconds</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-12 items-start mb-12">
              {/* Brand Col */}
              <div className="space-y-6">
                <div className="text-2xl font-bold tracking-tighter flex items-center gap-2">
                  <div className="w-8 h-8 bg-ink text-white flex items-center justify-center rounded-lg text-lg font-bold">P</div>
                  Pros<span className="text-blue-primary">Hub</span>
                </div>
                <p className="text-sm font-medium text-muted leading-relaxed max-w-xs">
                  The professional skills hub for the modern world. Hire verified specialists in seconds.
                </p>
                <div className="flex gap-4">
                  <button className="w-10 h-10 rounded-xl bg-paper flex items-center justify-center text-muted hover:text-ink hover:bg-border transition-all"><Twitter size={18}/></button>
                  <button className="w-10 h-10 rounded-xl bg-paper flex items-center justify-center text-muted hover:text-ink hover:bg-border transition-all"><Github size={18}/></button>
                  <button className="w-10 h-10 rounded-xl bg-paper flex items-center justify-center text-muted hover:text-ink hover:bg-border transition-all"><Linkedin size={18}/></button>
                  <button className="w-10 h-10 rounded-xl bg-paper flex items-center justify-center text-muted hover:text-ink hover:bg-border transition-all"><Instagram size={18}/></button>
                </div>
              </div>

              {/* Links Col 1 */}
              <div>
                <h4 className="font-bold uppercase tracking-widest text-xs mb-6 text-ink">Platform</h4>
                <ul className="space-y-4 text-sm font-bold text-muted">
                  <li><button onClick={() => setShowHowModal(true)} className="hover:text-blue-primary transition-colors">How it works</button></li>
                  <li><button onClick={() => setShowServicesModal(true)} className="hover:text-blue-primary transition-colors">Services</button></li>
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">Safety</Link></li>
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">Help Center</Link></li>
                </ul>
              </div>

              {/* Links Col 2 */}
              <div>
                <h4 className="font-black uppercase tracking-widest text-xs mb-6 text-ink">Company</h4>
                <ul className="space-y-4 text-sm font-bold text-muted">
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">About Us</Link></li>
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">Careers</Link></li>
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">Privacy Policy</Link></li>
                  <li><Link to="/login" className="hover:text-blue-primary transition-colors">Terms of Service</Link></li>
                </ul>
              </div>

              {/* Newsletter Col */}
              <div className="bg-paper p-6 rounded-3xl border-2 border-border">
                <h4 className="font-black uppercase tracking-widest text-xs mb-4 text-ink">Stay Updated</h4>
                <p className="text-xs font-medium text-muted mb-4">Get the latest skills and pro updates.</p>
                <div className="flex gap-2">
                  <input type="email" placeholder="Email" className="bg-white border-2 border-border rounded-xl px-3 py-2 text-xs font-bold outline-none focus:border-blue-primary w-full" />
                  <button className="bg-ink text-white p-2 rounded-xl hover:bg-blue-primary transition-all"><ArrowRight size={16}/></button>
                </div>
              </div>
            </div>
            <div className="h-px bg-border w-full mb-8"></div>
          </div>

          {/* Simple Footer - Always visible, primary on mobile */}
          <div className="flex flex-col md:flex-row justify-between items-center gap-6 text-xs font-medium text-muted/60">
            <div className="text-center md:text-left">© 2026 ProsHub. All Rights Reserved.</div>
            <div className="flex flex-col md:flex-row items-center gap-4 md:gap-8">
              <span>Built for Professionals</span>
              <span className="hidden md:block w-1 h-1 bg-muted/20 rounded-full"></span>
              <span>Direct Negotiation</span>
            </div>
          </div>
        </div>
      </footer>

      {/* --- MODALS --- */}

      {/* HOW IT WORKS MODAL */}
      <AnimatePresence>
        {showHowModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-ink/40 backdrop-blur-md"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              className="bg-white rounded-[40px] border border-blue-primary/20 shadow-[0_24px_80px_#2563eb15] max-w-5xl w-full p-10 relative overflow-y-auto max-h-[90vh]"
            >
              <button onClick={() => setShowHowModal(false)} className="absolute top-8 right-8 p-2 hover:bg-paper rounded-full transition-all">
                <X size={24} />
              </button>
              
              <div className="text-center mb-12">
                <h2 className="text-4xl font-black tracking-tight mb-4">How ProsHub Works</h2>
                <p className="text-muted font-bold">The simplest and most secure way to hire verified specialists.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {steps.map((step, i) => (
                  <div 
                    key={step.title} 
                    className="flex items-start gap-5 p-6 bg-paper border-2 border-border rounded-3xl hover:border-blue-primary hover:bg-white hover:shadow-[0_6px_20px_#2563eb20] transition-all group text-left"
                  >
                    <div className="p-4 bg-white rounded-2xl border-2 border-border group-hover:scale-110 transition-transform shrink-0">
                      {step.icon}
                    </div>
                    <div className="flex-1">
                      <div className="flex justify-between items-center mb-1">
                        <h3 className="font-black text-lg">{step.title}</h3>
                        <span className="text-[10px] font-black bg-blue-light text-blue-primary px-2 py-1 rounded-lg">
                          STEP {i + 1}
                        </span>
                      </div>
                      <p className="text-xs text-muted font-medium leading-relaxed">{step.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* WHY PROSHUB SECTION (Inside Modal) */}
              <div className="mt-16 pt-16 border-t border-border">
                <h3 className="text-3xl font-black mb-8 text-center">Why ProsHub is <span className="text-blue-primary">Different</span></h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                  <div className="space-y-3">
                    <div className="w-12 h-12 bg-blue-light text-blue-primary rounded-2xl flex items-center justify-center">
                      <Zap size={24} />
                    </div>
                    <h4 className="font-bold text-lg">Micro-Skills Focus</h4>
                    <p className="text-sm text-muted font-medium">We prioritize precision. Find specialists for exact needs, not just broad categories.</p>
                  </div>
                  <div className="space-y-3">
                    <div className="w-12 h-12 bg-gold/10 text-gold rounded-2xl flex items-center justify-center">
                      <ShieldCheck size={24} />
                    </div>
                    <h4 className="font-bold text-lg">The Verification Ring</h4>
                    <p className="text-sm text-muted font-medium">A dynamic trust system verifying Identity, Education, and Experience at a glance.</p>
                  </div>
                  <div className="space-y-3">
                    <div className="w-12 h-12 bg-green-light text-green-primary rounded-2xl flex items-center justify-center">
                      <TrendingUp size={24} />
                    </div>
                    <h4 className="font-bold text-lg">Growth Focused</h4>
                    <p className="text-sm text-muted font-medium">Build your reputation with our transparent review system and grow your business.</p>
                  </div>
                </div>
              </div>

              <div className="mt-8 md:mt-12 p-8 md:p-12 bg-ink text-white rounded-[32px] md:rounded-[48px] text-center relative overflow-hidden shadow-2xl">
                <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-blue-primary/20 via-transparent to-transparent"></div>
                <h3 className="text-3xl font-black mb-6 relative z-10">Ready to find your first pro?</h3>
                <Link to="/login" className="bg-blue-primary text-white px-12 py-5 rounded-[24px] font-black text-xl hover:bg-white hover:text-ink transition-all shadow-xl inline-block relative z-10">
                  Get Started Now
                </Link>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* SERVICES MODAL */}
      <AnimatePresence>
        {showServicesModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-ink/40 backdrop-blur-md"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              className="bg-white rounded-[40px] border border-blue-primary/20 shadow-[0_24px_80px_#2563eb15] max-w-5xl w-full p-10 relative overflow-y-auto max-h-[90vh]"
            >
              <button onClick={() => setShowServicesModal(false)} className="absolute top-8 right-8 p-2 hover:bg-paper rounded-full transition-all">
                <X size={24} />
              </button>
              
              <div className="text-center mb-12">
                <h2 className="text-4xl font-black tracking-tight mb-4">Our Services</h2>
                <p className="text-muted font-bold">Browse thousands of micro-skills across all industries.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                {allServices.map((service) => (
                  <button
                    key={service.name}
                    onClick={() => {
                      setShowServicesModal(false);
                      if (isAuthenticated) {
                        navigate(`/dashboard?search=${service.name}`);
                      } else {
                        navigate(`/login?search=${service.name}`);
                      }
                    }}
                    className="flex items-start gap-5 p-6 bg-paper border-2 border-border rounded-3xl hover:border-blue-primary hover:bg-white hover:shadow-[0_6px_20px_#2563eb20] transition-all group text-left"
                  >
                    <div className={`p-4 bg-white rounded-2xl border-2 border-border group-hover:scale-110 transition-transform`}>
                      {getIcon(service.name)}
                    </div>
                    <div className="flex-1">
                      <div className="flex justify-between items-center mb-1">
                        <h3 className="font-black text-lg">{service.name}</h3>
                        <span className="text-[10px] font-black bg-blue-light text-blue-primary px-2 py-1 rounded-lg">
                          {service.count} PROS
                        </span>
                      </div>
                      <p className="text-xs text-muted font-medium">Professional {service.name} services</p>
                    </div>
                  </button>
                ))}
              </div>

              <div className="mt-12 text-center">
                <p className="text-muted font-bold mb-4 italic">Don't see what you need? Use the search bar on the home page!</p>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
