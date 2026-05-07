// FILE: src/Dashboard.tsx — ProsHub Dashboard v7
// PURPOSE: Main app shell. Renders the correct view (overview/jobs/search/profile/admin)
//          based on sidebar selection. Holds all shared state and API calls.
// KEY CHANGES (v7):
//   - Added handleDeleteWork() — deletes a portfolio item + its file on the server.
//   - handleDeleteWork passed down to Profile component.
import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from './AuthContext';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { toast } from 'sonner';
import { Bell, MessageSquare, X, Send, WifiOff } from 'lucide-react';

import Sidebar         from './components/Dashboard/Sidebar';
import Overview        from './components/Dashboard/Overview';
import Jobs            from './components/Dashboard/Jobs';
import Search          from './components/Dashboard/Search';
import Verification, { type VerificationDocs } from './components/Dashboard/Verification';
import Profile         from './components/Dashboard/Profile';
import Modals          from './components/Dashboard/Modals';
import ProProfileModal from './components/Dashboard/ProProfileModal';
import SubscriptionModalInline from './components/Dashboard/SubscriptionModalInline';
import AdminDashboard  from './components/Dashboard/AdminDashboard';

const authHeader = (token: string) => ({ 'Authorization': `Bearer ${token}` });

export default function Dashboard() {
  const { user, token, logout, updateUser } = useAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // Admin always lands on admin panel
  const [view, setView] = useState<'overview'|'jobs'|'search'|'verification'|'profile'|'notifications'|'admin'>(
    user?.is_admin === 1 ? 'admin' : 'overview'
  );

  const [jobs, setJobs] = useState<any[]>([]);
  const [pendingJobs, setPendingJobs] = useState<any[]>([]);
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [categories, setCategories] = useState<any[]>([]);
  const [offers, setOffers] = useState<any[]>([]);
  const [messages, setMessages] = useState<any[]>([]);
  const [selectedJob, setSelectedJob] = useState<any>(null);

  // Notification quick-reply panel (inline chat from notification)
  const [notifChatJob, setNotifChatJob] = useState<any>(null);
  const [notifChatMessages, setNotifChatMessages] = useState<any[]>([]);
  const [notifChatInput, setNotifChatInput] = useState('');
  const notifChatEndRef = useRef<HTMLDivElement>(null);

  // Post job form
  const [showPostModal, setShowPostModal] = useState(false);
  const [postTitle, setPostTitle] = useState('');
  const [postDesc, setPostDesc] = useState('');
  const [postBudget, setPostBudget] = useState('');
  const [postLocation, setPostLocation] = useState('');
  const [postCategory, setPostCategory] = useState('');
  const [postFile, setPostFile] = useState<File | null>(null);
  const [postSkills, setPostSkills] = useState<string[]>([]);

  // Portfolio
  const [showWorkModal, setShowWorkModal] = useState(false);
  const [workTitle, setWorkTitle] = useState('');
  const [workDesc, setWorkDesc] = useState('');
  const [workImage, setWorkImage] = useState('');
  const [workFile, setWorkFile] = useState<File | null>(null);
  const [completedWorks, setCompletedWorks] = useState<any[]>([]);

  // Profile
  const [profileName, setProfileName] = useState(user?.name || '');
  const [profileBio, setProfileBio] = useState(user?.bio || '');
  const [profileAvatar, setProfileAvatar] = useState(user?.avatar || '');
  const [profileLocation, setProfileLocation] = useState(user?.location || '');
  const [profileSkills, setProfileSkills] = useState<string[]>(user?.skills || []);
  const [newSkill, setNewSkill] = useState('');
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [isPublicProfile, setIsPublicProfile] = useState(true);
  const [isPublicDocs, setIsPublicDocs] = useState(false);
  const [userDocuments, setUserDocuments] = useState<any[]>([]);

  // UI
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showProProfileModal, setShowProProfileModal] = useState(false);
  const [selectedPro, setSelectedPro] = useState<any>(null);
  const [fullProProfile, setFullProProfile] = useState<any>(null);
  const [showSubscriptionModal, setShowSubscriptionModal] = useState(false);
  const [subscriptionInfo, setSubscriptionInfo] = useState<any>(null);
  const [isAvailable, setIsAvailable] = useState(user?.is_available === 1);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [newMessage, setNewMessage] = useState('');
  const [searchQuery, setSearchQuery] = useState(searchParams.get('search') || '');
  const [localOnly, setLocalOnly] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);

  // Direct hire modal
  const [showDirectHireModal, setShowDirectHireModal] = useState(false);
  const [directHirePro, setDirectHirePro] = useState<any>(null);
  const [directHirePrice, setDirectHirePrice] = useState('');
  const [directHireDesc, setDirectHireDesc] = useState('');

  const socketRef = useRef<WebSocket | null>(null);
  const selectedJobRef = useRef(selectedJob);
  useEffect(() => { selectedJobRef.current = selectedJob; }, [selectedJob]);

  // Admin redirect — fires when user loads from auth context
  useEffect(() => {
    if (user?.is_admin === 1) setView('admin');
  }, [user?.is_admin]);

  useEffect(() => {
    if (user) {
      setIsAvailable(user.is_available === 1);
      setProfileName(user.name || '');
      setProfileBio(user.bio || '');
      setProfileAvatar(user.avatar || '');
      setProfileLocation(user.location || '');
      setProfileSkills(user.skills || []);
    }
  }, [user]);

  // ── API helpers ──────────────────────────────────────────────────────────────
  const fetchJobs = async () => {
    if (!token) return;
    try { const r = await fetch('/api/my-jobs', { headers: authHeader(token) }); if (r.ok) setJobs(await r.json()); } catch {}
  };
  const fetchPendingJobs = async () => {
    if (!token) return;
    try { const r = await fetch('/api/jobs/pending', { headers: authHeader(token) }); if (r.ok) setPendingJobs(await r.json()); } catch {}
  };
  const fetchNotifications = async () => {
    if (!token) return;
    try { const r = await fetch('/api/notifications', { headers: authHeader(token) }); if (r.ok) setNotifications(await r.json()); } catch {}
  };
  const fetchCategories = async () => {
    try {
      const r = await fetch('/api/stats/categories');
      if (r.ok) {
        const data = await r.json();
        // Merge API categories with comprehensive static list so all skill types always show
        const staticCats = [
          'Plumbing','Electrical','Cleaning','Gardening','Handyman','Painting',
          'IT & Tech','Tutoring','Moving','Marketing','Legal','Fitness','Carpentry',
          'HVAC','Roofing','Pest Control','Photography','Accounting','Driving',
          'Doctor','Dentist','Nursing','Engineering'
        ];
        const apiNames = new Set(data.map((c: any) => c.name));
        const merged = [...data];
        staticCats.forEach(name => { if (!apiNames.has(name)) merged.push({ name, count: 0 }); });
        setCategories(merged);
      }
    } catch {}
  };
  const fetchMessages = async (jobId: string) => {
    if (!token) return;
    try { const r = await fetch(`/api/jobs/${jobId}/messages`, { headers: authHeader(token) }); if (r.ok) setMessages(await r.json()); } catch {}
  };
  const fetchOffers = async (jobId: string) => {
    if (!token) return;
    try { const r = await fetch(`/api/jobs/${jobId}/offers`, { headers: authHeader(token) }); if (r.ok) setOffers(await r.json()); } catch {}
  };
  const fetchCompletedWorks = async () => {
    if (!token || !user?.id) return;
    try {
      // Use authenticated endpoint so pro can see ALL their own portfolio items including hidden
      const r = await fetch(`/api/user/completed-works`, { headers: authHeader(token) });
      if (r.ok) setCompletedWorks(await r.json());
    } catch {}
  };

  // DELETE a portfolio item (image/video) — pro can keep or remove their own uploads
  const handleDeleteWork = async (workId: string) => {
    if (!token || !window.confirm('Remove this item from your portfolio?')) return;
    try {
      const r = await fetch(`/api/user/completed-works/${workId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (r.ok) {
        // Refresh portfolio after deletion
        await fetchCompletedWorks();
      }
    } catch {}
  };

  // TOGGLE visibility of a portfolio item (show/hide like reviews)
  const handleToggleWorkVisibility = async (work: any) => {
    if (!token) return;
    try {
      const r = await fetch(`/api/user/completed-works/${work.id}/visibility`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ is_hidden: work.is_hidden ? 0 : 1 }),
      });
      if (r.ok) fetchCompletedWorks();
    } catch {}
  };
  const fetchUserDocuments = async () => {
    if (!token) return;
    try { const r = await fetch('/api/user/documents', { headers: authHeader(token) }); if (r.ok) setUserDocuments(await r.json()); } catch {}
  };
  const fetchProfile = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/user/profile', { headers: authHeader(token) });
      if (r.ok) {
        const d = await r.json();
        updateUser(d);
        setProfileName(d.name); setProfileBio(d.bio || ''); setProfileAvatar(d.avatar || '');
        setProfileLocation(d.location || ''); setProfileSkills(d.skills || []);
        setIsPublicProfile(d.is_public_profile === 1 || d.is_public_profile === true);
        setIsPublicDocs(d.is_public_docs === 1 || d.is_public_docs === true);
      }
    } catch {}
  };
  const fetchSubscription = async () => {
    if (!token) return;
    try {
      const r = await fetch('/api/user/subscription', { headers: authHeader(token) });
      if (r.ok) {
        const d = await r.json(); setSubscriptionInfo(d);
        if (user?.role === 'pro' && d.subscription_status === 'none') setShowSubscriptionModal(true);
      }
    } catch {}
  };

  // WebSocket — with auto-reconnect to prevent "offline" false positives
  const wsReconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wsConnected = useRef(false);
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  const connectWebSocket = React.useCallback(() => {
    if (!token) return;
    if (wsReconnectTimer.current) clearTimeout(wsReconnectTimer.current);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${window.location.host}`);
    socketRef.current = socket;

    socket.onopen = () => {
      wsConnected.current = true;
      socket.send(JSON.stringify({ type: 'auth', token }));
      // Refresh data on reconnect
      fetchJobs();
      fetchNotifications();
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'chat') {
          // Incoming chat message — add to both possible panels
          const newMsg = {
            id: data.messageId || Date.now(),
            job_id: data.jobId,
            sender_id: data.senderId,
            sender_name: data.senderName || 'Specialist',
            content: data.content,
            created_at: data.createdAt
          };
          if (selectedJobRef.current?.id === data.jobId) {
            setMessages(prev => {
              // Deduplicate: don't add if already present
              if (prev.some(m => m.id === newMsg.id)) return prev;
              return [...prev, newMsg];
            });
          }
          if (notifChatJob?.id === data.jobId) {
            setNotifChatMessages(prev => {
              if (prev.some(m => m.id === newMsg.id)) return prev;
              return [...prev, newMsg];
            });
          }
        }

        if (data.type === 'job_updated') {
          // Real-time job status update — refresh jobs list and update selected job
          fetchJobs();
          if (selectedJobRef.current?.id === data.jobId) {
            fetch(`/api/jobs/${data.jobId}`, { headers: authHeader(token!) })
              .then(r => r.ok ? r.json() : null)
              .then(job => { if (job) setSelectedJob(job); })
              .catch(() => {});
          }
        }

        if (data.type === 'offers_updated') {
          // Real-time new offer — refresh offers for current job
          if (selectedJobRef.current?.id === data.jobId) {
            fetch(`/api/jobs/${data.jobId}/offers`, { headers: authHeader(token!) })
              .then(r => r.ok ? r.json() : null)
              .then(offers => { if (offers) setOffers(offers); })
              .catch(() => {});
          }
        }

        if (data.type === 'notification_removed') {
          setNotifications(prev => prev.filter(n => n.id !== data.notificationId));
          if (notifChatJob?.id === data.jobId) {
            setNotifChatJob(null);
            toast.info('This job has been accepted by another professional.');
          }
        }

        if (data.type === 'notification') {
          // Add notification directly to state without refetching
          setNotifications(prev => [{
            id: data.id,
            content: data.content,
            type: data.notificationType,
            job_id: data.jobId,
            is_read: false,
            created_at: data.createdAt,
          }, ...prev]);
        }
      } catch { /* ignore malformed messages */ }
    };

    socket.onerror = () => {
      wsConnected.current = false;
    };

    socket.onclose = () => {
      wsConnected.current = false;
      // Auto-reconnect after 3 seconds — prevents false "offline" state
      wsReconnectTimer.current = setTimeout(() => {
        if (token) connectWebSocket();
      }, 3000);
    };
  }, [token]);

  useEffect(() => {
    if (!token) return;
    connectWebSocket();

    // Also reconnect when browser tab becomes visible again (user switches back)
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        if (!socketRef.current || socketRef.current.readyState === WebSocket.CLOSED) {
          connectWebSocket();
        }
        // Always refresh data when tab becomes visible
        fetchJobs();
        fetchNotifications();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    const handleOnline  = () => { setIsOnline(true);  fetchJobs(); fetchNotifications(); };
    const handleOffline = () => setIsOnline(false);
    window.addEventListener('online',  handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      if (wsReconnectTimer.current) clearTimeout(wsReconnectTimer.current);
      socketRef.current?.close();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('online',  handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [token, connectWebSocket]);

  // Initial load
  useEffect(() => {
    if (!token) return;
    fetchJobs(); fetchNotifications(); fetchCategories(); fetchProfile();
    if (user?.role === 'pro') { fetchPendingJobs(); fetchCompletedWorks(); fetchUserDocuments(); fetchSubscription(); }
    if (user?.role === 'client') { fetchUserDocuments(); }
    const query = searchParams.get('search');
    if (query) {
      setSearchQuery(query); setView('search');
      fetch(`/api/pros/search?query=${query}`, { headers: authHeader(token) })
        .then(r => r.json()).then(setSearchResults).catch(console.error);
    }
    if (new URLSearchParams(window.location.search).get('verification') === 'success') {
      toast.success('Identity documents submitted!'); fetchProfile();
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [token]);

  // Polling — reduced frequency for performance (WS handles real-time, polling is fallback)
  useEffect(() => {
    if (!token) return;
    const role = user?.role;
    const interval = setInterval(() => { 
      fetchJobs(); 
      fetchNotifications(); 
      if (role === 'pro') fetchPendingJobs(); 
    }, 60000); // 60s fallback (WebSocket handles real-time updates)
    return () => clearInterval(interval);
  }, [token, user?.role]);

  useEffect(() => {
    if (!selectedJob) return;
    fetchMessages(selectedJob.id); fetchOffers(selectedJob.id);
    // WebSocket handles real-time updates; 30s fallback just in case WS drops
    const interval = setInterval(() => { fetchMessages(selectedJob.id); fetchOffers(selectedJob.id); }, 30000);
    return () => clearInterval(interval);
  }, [selectedJob?.id]);

  useEffect(() => {
    if (view === 'notifications' && token) {
      fetch('/api/notifications/read', { method: 'POST', headers: authHeader(token) }).then(() => fetchNotifications());
    }
  }, [view, token]);

  useEffect(() => {
    if (!selectedPro || !showProProfileModal || !token) { setFullProProfile(null); return; }
    fetch(`/api/pro/${selectedPro.id}/full-profile`, { headers: authHeader(token) })
      .then(r => r.ok ? r.json() : null).then(setFullProProfile).catch(console.error);
  }, [selectedPro, showProProfileModal, token]);

  // Scroll notif chat to bottom
  useEffect(() => {
    notifChatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [notifChatMessages]);

  // Load messages when notifChatJob opens — WebSocket handles live updates
  useEffect(() => {
    if (!notifChatJob || !token) return;
    fetch(`/api/jobs/${notifChatJob.id}/messages`, { headers: authHeader(token) })
      .then(r => r.json()).then(setNotifChatMessages).catch(() => {});
    // No polling interval — WebSocket chat events keep this live
  }, [notifChatJob, token]);

  // ── Action Handlers ──────────────────────────────────────────────────────────

  const handleSearch = async (e?: React.FormEvent, queryOverride?: string) => {
    if (e) e.preventDefault();
    const q = (queryOverride ?? searchQuery).trim();
    if (queryOverride) setSearchQuery(queryOverride);
    setHasSearched(true);
    if (!q) return;
    setView('search');
    const doSearch = async (lat?: number, lng?: number) => {
      try {
        let url = `/api/pros/search?query=${encodeURIComponent(q)}&localOnly=${localOnly}`;
        if (lat && lng) url += `&lat=${lat}&lng=${lng}`;
        const res = await fetch(url, { headers: authHeader(token!) });
        if (res.ok) setSearchResults(await res.json());
      } catch {}
    };
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(p => doSearch(p.coords.latitude, p.coords.longitude), () => doSearch(), { timeout: 5000 });
    } else { doSearch(); }
  };

  const handlePostJob = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    // Validate description length (server requires min 10)
    const descTrimmed = postDesc.trim();
    if (descTrimmed.length < 10) {
      toast.error('Description must be at least 10 characters.');
      return;
    }
    const formData = new FormData();
    formData.append('title', postTitle.trim());
    formData.append('description', descTrimmed);
    formData.append('price', postBudget || '0');
    formData.append('location', postLocation.trim() || 'Remote');
    formData.append('category', postCategory);
    // Always ensure at least the category is in required_skills
    const skills = postSkills.length > 0 ? postSkills : (postCategory ? [postCategory] : []);
    formData.append('required_skills', JSON.stringify(skills));
    if (postFile) formData.append('file', postFile);
    try {
      const res = await fetch('/api/jobs', { method: 'POST', headers: authHeader(token), body: formData });
      if (res.ok) {
        setShowPostModal(false);
        setPostTitle(''); setPostDesc(''); setPostBudget(''); setPostLocation(''); setPostCategory(''); setPostFile(null); setPostSkills([]);
        fetchJobs(); toast.success('Job posted to matching professionals!');
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.error || 'Failed to post job. Please check all fields and try again.');
      }
    } catch { toast.error('Network error. Please try again.'); }
  };

  const handleDirectHire = async () => {
    if (!token || !directHirePro || !directHirePrice) return;
    // Ensure description meets 10-char minimum
    const rawDesc = directHireDesc.trim() ||
      `Direct hire request for ${directHirePro.name}${directHirePro.skills?.length ? ' - ' + directHirePro.skills.slice(0,2).join(', ') : ' - professional services'}`;
    const description = rawDesc.length >= 10 ? rawDesc : rawDesc + ' - please discuss details via chat';
    const formData = new FormData();
    formData.append('title', `Hire ${directHirePro.name}`.substring(0, 119));
    formData.append('description', description);
    formData.append('price', String(Number(directHirePrice) || 0));
    formData.append('location', user?.location || 'Remote');
    formData.append('category', directHirePro.skills?.[0] || 'General');
    formData.append('pro_id', directHirePro.id);
    formData.append('required_skills', JSON.stringify(directHirePro.skills || []));
    formData.append('is_direct_hire', 'true');
    try {
      const res = await fetch('/api/jobs', { method: 'POST', headers: authHeader(token), body: formData });
      if (res.ok) {
        const job = await res.json();
        setShowDirectHireModal(false); setDirectHirePro(null); setDirectHirePrice(''); setDirectHireDesc('');
        setShowProProfileModal(false);
        fetchJobs(); setSelectedJob(job); setView('jobs');
        toast.success(`Hire request sent to ${directHirePro.name}!`);
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.error || 'Failed to send hire request.');
      }
    } catch { toast.error('Network error. Please try again.'); }
  };

  const openDirectChat = async (pro: any) => {
    if (!token) return;
    const existingJob = jobs.find(j =>
      (j.pro_id === pro.id && j.client_id === user?.id) ||
      (j.client_id === pro.id && j.pro_id === user?.id)
    );
    if (existingJob) { setSelectedJob(existingJob); return; }
    try {
      const formData = new FormData();
      formData.append('title', `Chat with ${pro.name}`.substring(0, 119));
      formData.append('description', `Direct chat and enquiry with ${pro.name} regarding professional services`);
      formData.append('price', '0');
      formData.append('location', user?.location || 'Remote');
      formData.append('category', pro.skills?.[0] || 'General');
      formData.append('pro_id', pro.id);
      formData.append('required_skills', JSON.stringify(pro.skills || []));
      formData.append('is_direct_message', 'true');
      formData.append('_clientName', user?.name || 'A client');
      const res = await fetch('/api/jobs', { method: 'POST', headers: authHeader(token), body: formData });
      if (res.ok) { const job = await res.json(); fetchJobs(); setSelectedJob(job); }
      else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.error || 'Could not open chat.');
      }
    } catch { toast.error('Could not open chat.'); }
  };

  const handleCancelJob = async (jobId: string) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST', headers: authHeader(token) });
    if (res.ok) { toast.success('Job request cancelled.'); setSelectedJob(null); fetchJobs(); fetchPendingJobs(); }
    else toast.error('Failed to cancel job.');
  };

  // HIRE AGAIN — client re-sends a hire request to the same pro from a finalized job
  const handleHireAgain = (job: any) => {
    if (!job.pro_id) return;
    const pro = { id: job.pro_id, name: job.pro_name || 'Professional', skills: job.required_skills || [] };
    setDirectHirePro(pro);
    setDirectHireDesc(`Follow-up: ${job.title}`);
    setDirectHirePrice(String(job.final_price || job.initial_price || ''));
    setShowDirectHireModal(true);
  };

  // Notification click — opens inline chat panel instead of navigating away
  const handleNotificationClick = async (notification: any) => {
    if (!token) return;
    fetch(`/api/notifications/${notification.id}/read`, { method: 'POST', headers: authHeader(token) })
      .then(() => fetchNotifications()).catch(() => {});

    // FIX: verification_update notifications navigate to the Verification tab so pros can see reason and re-upload
    if (notification.type === 'verification_update') {
      setView('verification');
      return;
    }

    if (notification.job_id) {
      try {
        const res = await fetch(`/api/jobs/${notification.job_id}`, { headers: authHeader(token) });
        if (res.ok) {
          const job = await res.json();
          // Open inline chat panel on the notification page itself
          setNotifChatJob(job);
          setNotifChatMessages([]);
        } else {
          toast.error('Could not load that job — it may have been deleted.');
        }
      } catch { toast.error('Failed to open job.'); }
    }
  };

  // Send message from the notification inline chat panel
  const handleNotifChatSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!notifChatInput.trim() || !notifChatJob || !token) return;
    // Check if job is locked
    if (notifChatJob.status === 'finalized' || notifChatJob.locked) {
      toast.error('This job is complete — the chat is locked.');
      return;
    }
    const res = await fetch(`/api/jobs/${notifChatJob.id}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader(token) },
      body: JSON.stringify({ content: notifChatInput }),
    });
    if (res.ok) {
      const savedMessage = await res.json();
      const recipientId = user?.role === 'client' ? notifChatJob.pro_id : notifChatJob.client_id;
      if (recipientId && socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(JSON.stringify({ type: 'chat', jobId: notifChatJob.id, content: notifChatInput, recipientId }));
      }
      setNotifChatMessages(prev => [...prev, { ...savedMessage, sender_name: user?.name }]);
      setNotifChatInput('');
    } else {
      const err = await res.json().catch(() => ({}));
      toast.error(err.error || 'Failed to send message.');
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim() || !selectedJob || !token) return;
    // Check lock
    if (selectedJob.status === 'finalized' || selectedJob.locked) {
      toast.error('This job is complete — the chat is locked.');
      return;
    }
    let recipientId = user?.role === 'client' ? selectedJob.pro_id : selectedJob.client_id;
    if (user?.role === 'client' && !recipientId && messages.length > 0) {
      const lastProMsg = [...messages].reverse().find(m => m.sender_id !== user.id);
      if (lastProMsg) recipientId = lastProMsg.sender_id;
    }
    if (!recipientId) return;
    const res = await fetch(`/api/jobs/${selectedJob.id}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader(token) },
      body: JSON.stringify({ content: newMessage }),
    });
    if (res.ok) {
      const savedMessage = await res.json();
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(JSON.stringify({ type: 'chat', jobId: selectedJob.id, content: newMessage, recipientId }));
      }
      setMessages(prev => [...prev, { ...savedMessage, sender_name: user?.name }]);
      setNewMessage('');
    } else {
      const err = await res.json().catch(() => ({}));
      toast.error(err.error || 'Failed to send message.');
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault(); setIsSavingProfile(true);
    // Try to get coordinates from browser geolocation if location changed
    let location_lat: number | null = null;
    let location_lng: number | null = null;
    try {
      if (profileLocation && navigator.geolocation) {
        const pos = await new Promise<GeolocationPosition | null>((resolve) => {
          navigator.geolocation.getCurrentPosition(resolve, () => resolve(null), { timeout: 5000 });
        });
        if (pos) {
          location_lat = pos.coords.latitude;
          location_lng = pos.coords.longitude;
        }
      }
    } catch { /* non-fatal */ }
    const body: any = { name: profileName, bio: profileBio, skills: profileSkills, avatar: profileAvatar, location: profileLocation };
    if (location_lat !== null) body.location_lat = location_lat;
    if (location_lng !== null) body.location_lng = location_lng;
    const res = await fetch('/api/user/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...authHeader(token!) },
      body: JSON.stringify(body),
    });
    setIsSavingProfile(false);
    if (res.ok) {
      const data = await res.json();
      updateUser({ ...user!, name: profileName, bio: profileBio, skills: data.skills || profileSkills, avatar: profileAvatar, location: profileLocation });
      if (data.skills) setProfileSkills(data.skills);
      toast.success('Profile saved!');
    } else toast.error('Failed to save profile.');
  };

  const handleToggleVisibility = async (type: 'profile' | 'docs', value: boolean) => {
    if (!token || !user) return;
    const res = await fetch('/api/user/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...authHeader(token) },
      body: JSON.stringify({ name: profileName, bio: profileBio, skills: profileSkills, avatar: profileAvatar, location: profileLocation, is_public_profile: type === 'profile' ? value : isPublicProfile, is_public_docs: type === 'docs' ? value : isPublicDocs }),
    });
    if (res.ok) { if (type === 'profile') setIsPublicProfile(value); else setIsPublicDocs(value); fetchProfile(); }
  };

  const handleUploadDocument = async (title: string, url: string) => {
    if (!token) return;
    const res = await fetch('/api/user/documents', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader(token) }, body: JSON.stringify({ title, file_url: url }) });
    if (res.ok) fetchUserDocuments(); else toast.error('Failed to upload document.');
  };
  const handleDeleteDocument = async (id: string) => {
    if (!token) return;
    await fetch(`/api/user/documents/${id}`, { method: 'DELETE', headers: authHeader(token) });
    fetchUserDocuments();
  };
  const handleVerification = async (docs: VerificationDocs) => {
    setIsVerifying(true);
    try {
      // Upload each verification doc tagged with is_verification_doc=true so admin can see them
      const uploads: Array<{ file: File; title: string }> = [];
      if (docs.idFile) uploads.push({ file: docs.idFile, title: `ID Document (${docs.idType})` });
      if (docs.certFile) uploads.push({ file: docs.certFile, title: 'Professional Certificate' });
      if (docs.expFile) uploads.push({ file: docs.expFile, title: 'Experience Document' });

      for (const { file, title } of uploads) {
        const fd = new FormData();
        fd.append('title', title);
        fd.append('file', file);
        fd.append('is_verification_doc', 'true');
        const r = await fetch('/api/user/documents/upload', {
          method: 'POST',
          headers: authHeader(token!),
          body: fd,
        });
        if (!r.ok) throw new Error('Upload failed for ' + title);
      }

      // Mark status as pending review (50) — also notifies admin
      const res = await fetch('/api/user/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeader(token!) },
        body: JSON.stringify({ status: 50 }),
      });
      setIsVerifying(false);
      if (res.ok) {
        toast.success('Documents submitted! Verification within 24–48 hours.');
        fetchProfile();
        fetchUserDocuments(); // Refresh so pro sees their docs in Profile
        setView('overview');
      } else {
        toast.error('Submission failed. Please try again.');
      }
    } catch {
      setIsVerifying(false);
      toast.error('Submission failed. Please try again.');
    }
  };
  const handleAddWork = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    const formData = new FormData();
    formData.append('title', workTitle); formData.append('description', workDesc);
    if (workFile) { formData.append('file', workFile); }
    else if (workImage && !workImage.startsWith('data:')) { formData.append('image_url', workImage); }
    const res = await fetch('/api/pro/portfolio/upload', { method: 'POST', headers: authHeader(token), body: formData });
    if (res.ok) {
      setShowWorkModal(false); setWorkTitle(''); setWorkDesc(''); setWorkImage(''); setWorkFile(null);
      fetchCompletedWorks(); toast.success('Work added to portfolio!');
    } else {
      const err = await res.json().catch(() => ({}));
      toast.error(err.error || 'Failed to add work sample.');
    }
  };
  const handleToggleAvailability = async () => {
    if (!token) return;
    const next = !isAvailable;
    const res = await fetch('/api/user/availability', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader(token) }, body: JSON.stringify({ is_available: next }) });
    if (res.ok) { setIsAvailable(next); updateUser({ ...user!, is_available: next ? 1 : 0 }); }
  };
  const handleAcceptJob = async (jobId: string) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/accept`, { method: 'POST', headers: authHeader(token) });
    if (res.ok) {
      toast.success('Job accepted!'); fetchJobs(); fetchPendingJobs();
      const updated = await (await fetch(`/api/jobs/${jobId}`, { headers: authHeader(token) })).json();
      setSelectedJob(updated);
    } else toast.error((await res.json()).error || 'Failed to accept job.');
  };
  const handleConfirmMatch = async (jobId: string) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/confirm-match`, { method: 'POST', headers: authHeader(token) });
    if (res.ok) {
      toast.success('Match confirmed! Job is now active.'); fetchJobs();
      const updated = await (await fetch(`/api/jobs/${jobId}`, { headers: authHeader(token) })).json();
      setSelectedJob(updated);
    } else toast.error((await res.json()).error || 'Failed to confirm match.');
  };
  const handleMarkDone = async (jobId: string) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/mark-done`, { method: 'POST', headers: authHeader(token) });
    if (res.ok) {
      toast.success('Job marked as done! Client will be notified to confirm.');
      fetchJobs();
      const updated = await (await fetch(`/api/jobs/${jobId}`, { headers: authHeader(token) })).json();
      setSelectedJob(updated);
    } else toast.error((await res.json()).error || 'Failed to mark job as done.');
  };
  const handleCompleteJob = async (jobId: string, rating?: number, comment?: string) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/complete`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader(token) }, body: JSON.stringify({ rating, comment }) });
    if (res.ok) {
      toast.success(rating ? 'Job complete! Review submitted. Thank you!' : 'Job closed successfully!');
      fetchJobs(); fetchProfile(); setSelectedJob(null);
    } else toast.error((await res.json()).error || 'Failed to complete job.');
  };
  const handleAcceptOffer = async (offerId: string) => {
    if (!token) return;
    const res = await fetch(`/api/offers/${offerId}/accept`, { method: 'POST', headers: authHeader(token) });
    if (res.ok) {
      toast.success('Offer accepted!'); fetchJobs();
      if (selectedJob) { const updated = await (await fetch(`/api/jobs/${selectedJob.id}`, { headers: authHeader(token) })).json(); setSelectedJob(updated); }
    } else toast.error((await res.json()).error || 'Failed to accept offer.');
  };
  const handleNegotiate = async (jobId: string, amount: number) => {
    if (!token) return;
    const res = await fetch(`/api/jobs/${jobId}/offers`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader(token) }, body: JSON.stringify({ amount }) });
    if (res.ok) { toast.success('Offer sent!'); fetchOffers(jobId); }
    else toast.error((await res.json()).error || 'Failed to send offer.');
  };
  const handleDeleteAccount = async () => {
    if (!token) return;
    const res = await fetch('/api/user/account', { method: 'DELETE', headers: authHeader(token) });
    if (res.ok) { logout(); navigate('/'); } else toast.error('Failed to delete account.');
  };
  const handleStartTrial = async () => {
    if (!token) return;
    const res = await fetch('/api/subscription/start-trial', { method: 'POST', headers: authHeader(token) });
    if (res.ok) { fetchSubscription(); toast.success('6-month free trial started!'); }
  };
  const handleSubscribe = async () => {
    if (!token) return;
    const res = await fetch('/api/subscription/subscribe', { method: 'POST', headers: authHeader(token) });
    if (res.ok) { fetchSubscription(); toast.success('You are now a Pro subscriber!'); }
  };
  const handleStartStripeVerification = () => toast.info('Stripe Identity verification coming soon. Please use manual upload.');

  const unreadCount = notifications.filter(n => !n.is_read).length;

  const handleSetView = (v: typeof view) => {
    if (v !== 'search') { setSearchResults([]); setHasSearched(false); setSearchQuery(''); }
    if (v !== 'notifications') setNotifChatJob(null);
    setView(v);
  };

  return (
    <div className="min-h-screen bg-paper flex flex-col lg:flex-row">
      {/* Offline / connection lost banner */}
      {!isOnline && (
        <div className="fixed top-0 inset-x-0 z-[500] flex items-center justify-center gap-2 px-4 py-2 bg-red-500 text-white text-xs font-bold shadow-lg">
          <WifiOff size={14} />
          You are offline — reconnecting when network is available…
        </div>
      )}
      <Sidebar
        view={view} setView={handleSetView} user={user} logout={logout}
        isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen}
        notificationsCount={unreadCount} isAvailable={isAvailable}
        onToggleAvailability={handleToggleAvailability}
        onShowSubscription={() => setShowSubscriptionModal(true)}
      />

      <main className="flex-1 p-4 sm:p-6 lg:p-12 overflow-y-auto lg:max-h-screen min-w-0">
        <div className="max-w-7xl mx-auto">

          {view === 'overview' && (
            <Overview user={user} pendingJobs={pendingJobs} jobs={jobs} setView={handleSetView} onPostJob={() => setShowPostModal(true)} setSelectedJob={setSelectedJob} onCancelJob={handleCancelJob} />
          )}

          {view === 'jobs' && (
            <Jobs user={user} jobs={jobs} setSelectedJob={setSelectedJob} onCancelJob={handleCancelJob} onHireAgain={handleHireAgain} />
          )}

          {view === 'search' && (
            <Search
              searchQuery={searchQuery} setSearchQuery={setSearchQuery}
              handleSearch={handleSearch} searchResults={searchResults}
              categories={categories} navigate={navigate}
              onViewProfile={pro => { setSelectedPro(pro); setShowProProfileModal(true); }}
              onDirectHire={pro => { setDirectHirePro(pro); setShowDirectHireModal(true); }}
              onDirectChat={openDirectChat}
              localOnly={localOnly} setLocalOnly={setLocalOnly}
              hasSearched={hasSearched} userRole={user?.role}
            />
          )}

          {view === 'verification' && (
            <Verification user={user} isVerifying={isVerifying} handleVerification={handleVerification} onStartStripeVerification={handleStartStripeVerification} />
          )}

          {/* NOTIFICATIONS — with inline chat reply panel */}
          {view === 'notifications' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-3xl font-bold">Notifications</h2>
                {unreadCount > 0 && <span className="text-xs font-bold text-blue-primary bg-blue-light px-3 py-1 rounded-full">{unreadCount} unread</span>}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
                {/* Notification list */}
                <div className="space-y-3">
                  {notifications.length === 0 ? (
                    <div className="p-12 text-center bg-white border border-blue-primary/20 rounded-[32px] font-bold text-muted">No notifications yet.</div>
                  ) : (
                    notifications.map(n => (
                      <button
                        key={n.id}
                        onClick={() => handleNotificationClick(n)}
                        className={`w-full text-left bg-white border p-4 sm:p-5 rounded-[20px] shadow-[0_2px_10px_#2563eb15] flex items-start gap-3 sm:gap-4 transition-all hover:shadow-[0_6px_20px_#2563eb30] hover:border-blue-primary ${notifChatJob?.id === n.job_id ? 'border-blue-primary bg-blue-50 shadow-[0_6px_20px_#2563eb30]' : n.is_read ? 'border-blue-primary/20 opacity-70' : 'border-blue-primary bg-blue-50'}`}
                      >
                        <div className={`p-2.5 rounded-xl shrink-0 ${n.type === 'message' ? 'bg-green-light text-green-primary' : n.type === 'review_request' ? 'bg-gold/10 text-gold' : 'bg-blue-light text-blue-primary'}`}>
                          {n.type === 'message' ? <MessageSquare size={18} /> : <Bell size={18} />}
                        </div>
                        <div className="flex-1 min-w-0">
                          {n.title && <p className="font-black text-ink text-sm mb-0.5">{n.title}</p>}
                          <p className="font-medium text-ink/80 text-sm line-clamp-2">{n.content}</p>
                          <p className="text-[10px] text-muted font-bold uppercase tracking-widest mt-1">{new Date(n.created_at).toLocaleString()}</p>
                        </div>
                        {!n.is_read && <span className="w-2.5 h-2.5 rounded-full bg-blue-primary shrink-0 mt-1.5" />}
                        {(n.job_id || n.type === 'verification_update') && (
                          <span className="text-[9px] font-bold text-blue-primary bg-blue-light/80 px-2 py-1 rounded-lg shrink-0 whitespace-nowrap">
                            {n.type === 'message' ? '💬 REPLY' : n.type === 'verification_update' ? '🔍 OPEN' : '→ OPEN'}
                          </span>
                        )}
                      </button>
                    ))
                  )}
                </div>

                {/* Inline chat panel — appears when notification is clicked */}
                <div className="lg:sticky lg:top-4">
                  {notifChatJob ? (
                    <div className="bg-white border-2 border-blue-primary/30 rounded-[28px] overflow-hidden shadow-[0_8px_40px_#2563eb20] flex flex-col" style={{ height: 'min(70vh, 520px)' }}>
                      {/* Chat header */}
                      <div className="px-5 py-4 border-b border-blue-primary/20 bg-paper flex items-center justify-between shrink-0">
                        <div className="min-w-0">
                          <p className="font-black text-sm truncate">{notifChatJob.title}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border ${notifChatJob.status === 'finalized' || notifChatJob.locked ? 'bg-red-50 text-red-400 border-red-200' : 'bg-green-light text-green-primary border-green-primary/30'}`}>
                              {notifChatJob.status === 'finalized' || notifChatJob.locked ? '🔒 Locked' : '● Live Chat'}
                            </span>
                            {notifChatJob.pro_name && <span className="text-[10px] text-muted font-medium">with {notifChatJob.pro_name || notifChatJob.client_name}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            onClick={() => { setSelectedJob(notifChatJob); setNotifChatJob(null); setView('jobs'); }}
                            className="text-[10px] font-bold text-blue-primary bg-blue-light px-3 py-1.5 rounded-xl hover:bg-blue-primary hover:text-white transition-all"
                          >
                            Full View →
                          </button>
                          <button onClick={() => setNotifChatJob(null)} className="p-1.5 hover:bg-paper rounded-lg">
                            <X size={16} />
                          </button>
                        </div>
                      </div>

                      {/* Messages */}
                      <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-slate-50">
                        {notifChatMessages.length === 0 ? (
                          <div className="h-full flex flex-col items-center justify-center text-center p-6">
                            <div className="w-12 h-12 bg-blue-light text-blue-primary rounded-2xl flex items-center justify-center mb-3"><MessageSquare size={22} /></div>
                            <p className="text-sm font-bold text-muted">No messages yet</p>
                            <p className="text-xs text-muted/60 mt-1">Start the conversation below</p>
                          </div>
                        ) : notifChatMessages.map((msg, i) => {
                          const isMe = msg.sender_id === user?.id;
                          const showName = i === 0 || notifChatMessages[i-1].sender_id !== msg.sender_id;
                          return (
                            <div key={msg.id} className={`flex flex-col ${isMe ? 'items-end' : 'items-start'}`}>
                              {showName && <div className={`text-[10px] font-black uppercase tracking-widest mb-1 px-1 ${isMe ? 'text-blue-primary' : 'text-muted'}`}>{isMe ? 'You' : (msg.sender_name || 'Specialist')}</div>}
                              <div className={`max-w-[85%] px-4 py-2.5 rounded-2xl shadow-sm text-sm font-medium leading-relaxed ${isMe ? 'bg-ink text-white rounded-tr-none' : 'bg-white border-2 border-border text-ink rounded-tl-none'}`}>
                                {msg.content}
                                <div className={`text-[9px] mt-1 ${isMe ? 'text-white/40' : 'text-muted'}`}>{new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                              </div>
                            </div>
                          );
                        })}
                        <div ref={notifChatEndRef} />
                      </div>

                      {/* Input or locked message */}
                      {(notifChatJob.status === 'finalized' || notifChatJob.locked) ? (
                        <div className="p-4 border-t border-border bg-white shrink-0">
                          <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-xl">
                            <span className="text-sm">🔒</span>
                            <p className="text-xs font-bold text-red-500">This job is complete — chat is locked</p>
                          </div>
                        </div>
                      ) : (
                        <form onSubmit={handleNotifChatSend} className="p-3 border-t border-blue-primary/20 bg-white shrink-0">
                          <div className="flex gap-2">
                            <input
                              type="text"
                              placeholder="Reply here..."
                              className="flex-1 px-4 py-2.5 bg-paper border-2 border-border rounded-2xl font-medium outline-none focus:border-blue-primary text-sm transition-all"
                              value={notifChatInput}
                              onChange={e => setNotifChatInput(e.target.value)}
                            />
                            <button type="submit" disabled={!notifChatInput.trim()} className="bg-blue-primary text-white p-2.5 rounded-2xl hover:bg-blue-dark disabled:opacity-40 transition-all shrink-0">
                              <Send size={16} />
                            </button>
                          </div>
                        </form>
                      )}
                    </div>
                  ) : (
                    <div className="p-10 text-center bg-white border-2 border-dashed border-blue-primary/20 rounded-[28px]">
                      <div className="w-14 h-14 bg-blue-light text-blue-primary rounded-2xl flex items-center justify-center mx-auto mb-4"><MessageSquare size={26} /></div>
                      <p className="font-bold text-muted text-sm">Tap a notification to reply</p>
                      <p className="text-xs text-muted/60 mt-1">Chat opens right here — no back and forth</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {view === 'profile' && (
            <Profile
              user={user} profileName={profileName} setProfileName={setProfileName}
              profileBio={profileBio} setProfileBio={setProfileBio}
              profileAvatar={profileAvatar} setProfileAvatar={setProfileAvatar}
              profileLocation={profileLocation} setProfileLocation={setProfileLocation}
              profileSkills={profileSkills} setProfileSkills={setProfileSkills}
              newSkill={newSkill} setNewSkill={setNewSkill}
              isSavingProfile={isSavingProfile} handleSaveProfile={handleSaveProfile}
              setShowDeleteModal={setShowDeleteModal}
              isPublicProfile={isPublicProfile} setIsPublicProfile={setIsPublicProfile}
              isPublicDocs={isPublicDocs} setIsPublicDocs={setIsPublicDocs}
              handleToggleVisibility={handleToggleVisibility}
              userDocuments={userDocuments}
              handleUploadDocument={handleUploadDocument}
              handleDeleteDocument={handleDeleteDocument}
              handleDeleteWork={handleDeleteWork}
              handleToggleWorkVisibility={handleToggleWorkVisibility}
              logout={logout} setShowWorkModal={setShowWorkModal}
              token={token} completedWorks={completedWorks}
            />
          )}

          {view === 'admin' && user?.is_admin === 1 && (
            <AdminDashboard token={token} user={user} />
          )}
        </div>
      </main>

      <Modals
        showPostModal={showPostModal} setShowPostModal={setShowPostModal} handlePostJob={handlePostJob}
        postTitle={postTitle} setPostTitle={setPostTitle} postDesc={postDesc} setPostDesc={setPostDesc}
        postBudget={postBudget} setPostBudget={setPostBudget} postLocation={postLocation} setPostLocation={setPostLocation}
        postCategory={postCategory} setPostCategory={setPostCategory}
        postSkills={postSkills} setPostSkills={setPostSkills}
        categories={categories} postFile={postFile} setPostFile={setPostFile}
        selectedJob={selectedJob} setSelectedJob={setSelectedJob}
        messages={messages} newMessage={newMessage} setNewMessage={setNewMessage}
        offers={offers} handleSendMessage={handleSendMessage}
        user={user} token={token}
        showWorkModal={showWorkModal} setShowWorkModal={setShowWorkModal}
        handleAddWork={handleAddWork} workTitle={workTitle} setWorkTitle={setWorkTitle}
        workDesc={workDesc} setWorkDesc={setWorkDesc} workImage={workImage} setWorkImage={setWorkImage}
        workFile={workFile} setWorkFile={setWorkFile}
        showDeleteModal={showDeleteModal} setShowDeleteModal={setShowDeleteModal}
        handleDeleteAccount={handleDeleteAccount}
        isPublicProfile={isPublicProfile} setIsPublicProfile={setIsPublicProfile}
        isPublicDocs={isPublicDocs} setIsPublicDocs={setIsPublicDocs}
        handleToggleVisibility={handleToggleVisibility} userDocuments={userDocuments}
        handleUploadDocument={handleUploadDocument} handleDeleteDocument={handleDeleteDocument}
        onAcceptJob={handleAcceptJob} onConfirmMatch={handleConfirmMatch}
        onCompleteJob={handleCompleteJob} onMarkDone={handleMarkDone} onAcceptOffer={handleAcceptOffer}
        onNegotiate={handleNegotiate} onCancelJob={handleCancelJob}
        showDirectHireModal={showDirectHireModal} setShowDirectHireModal={setShowDirectHireModal}
        directHirePro={directHirePro} directHirePrice={directHirePrice} setDirectHirePrice={setDirectHirePrice}
        directHireDesc={directHireDesc} setDirectHireDesc={setDirectHireDesc}
        handleDirectHire={handleDirectHire}
      />

      <AnimatePresence>
        {showProProfileModal && (
          <ProProfileModal
            pro={fullProProfile || selectedPro}
            onClose={() => setShowProProfileModal(false)}
            onHire={pro => { setDirectHirePro(pro); setShowProProfileModal(false); setShowDirectHireModal(true); }}
            onChat={pro => { setShowProProfileModal(false); openDirectChat(pro); }}
            userRole={user?.role}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showSubscriptionModal && (
          <SubscriptionModalInline
            onClose={() => setShowSubscriptionModal(false)}
            onStartTrial={handleStartTrial} onSubscribe={handleSubscribe}
            subscriptionStatus={subscriptionInfo?.subscription_status || 'none'}
            trialEndsAt={subscriptionInfo?.trial_ends_at}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
