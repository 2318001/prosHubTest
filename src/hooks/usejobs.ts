// FILE: src/hooks/usejobs.ts — Custom hook for job CRUD: post, accept, negotiate price, confirm match, and complete.

import { useState, useCallback } from 'react';
import { toast } from 'sonner';
import { Job, User } from '../types';

export function useJobs(token: string | null, user: User | null) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [pendingJobs, setPendingJobs] = useState<Job[]>([]);
  const [searchResults, setSearchResults] = useState<User[]>([]);
  const [isPostingJob, setIsPostingJob] = useState(false);
  const [isAcceptingJob, setIsAcceptingJob] = useState(false);
  const [isConfirmingMatch, setIsConfirmingMatch] = useState(false);
  const [isCompletingJob, setIsCompletingJob] = useState(false);
  const [isAcceptingOffer, setIsAcceptingOffer] = useState(false);
  const [isNegotiating, setIsNegotiating] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [localOnly, setLocalOnly] = useState(false);

  const categories = [
    'Plumbing', 'Electrical', 'Carpentry', 'Cleaning', 'Painting',
    'Landscaping', 'Roofing', 'HVAC', 'Pest Control', 'Appliance Repair',
    'Moving', 'Handyman', 'Locksmith', 'Security', 'IT Support'
  ];

  const fetchJobs = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/my-jobs', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setJobs(await res.json());
      } else {
        toast.error('Failed to fetch jobs');
      }
    } catch (err) {
      console.error('Failed to fetch jobs', err);
      toast.error('Network error while fetching jobs');
    }
  }, [token]);

  const fetchPendingJobs = useCallback(async () => {
    if (!token || user?.role !== 'pro') return;
    try {
      const res = await fetch('/api/jobs/pending', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setPendingJobs(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch pending jobs', err);
    }
  }, [token, user?.role]);

  const handlePostJob = async (jobData: any) => {
    if (!token) return;
    setIsPostingJob(true);
    try {
      const formData = new FormData();
      Object.keys(jobData).forEach(key => {
        if (jobData[key] !== null) formData.append(key, jobData[key]);
      });

      const res = await fetch('/api/jobs', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      if (res.ok) {
        toast.success('Job broadcasted successfully!');
        fetchJobs();
        return true;
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to post job');
        return false;
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
      return false;
    } finally {
      setIsPostingJob(false);
    }
  };

  const handleAcceptJob = async (jobId: number) => {
    if (!token) return;
    setIsAcceptingJob(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/accept`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success('Job accepted! Waiting for client confirmation.');
        fetchJobs();
        fetchPendingJobs();
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to accept job');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsAcceptingJob(false);
    }
  };

  const handleConfirmMatch = async (jobId: number) => {
    if (!token) return;
    setIsConfirmingMatch(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/confirm-match`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success('Match confirmed! You can now start the job.');
        fetchJobs();
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to confirm match');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsConfirmingMatch(false);
    }
  };

  const handleCompleteJob = async (jobId: number, rating: number, comment: string) => {
    if (!token) return;
    setIsCompletingJob(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ rating, comment })
      });
      if (res.ok) {
        toast.success('Job marked as completed!');
        fetchJobs();
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to complete job');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsCompletingJob(false);
    }
  };

  const handleAcceptOffer = async (offerId: number) => {
    if (!token) return;
    setIsAcceptingOffer(true);
    try {
      const res = await fetch(`/api/offers/${offerId}/accept`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success('Offer accepted!');
        fetchJobs();
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to accept offer');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsAcceptingOffer(false);
    }
  };

  const handleNegotiate = async (jobId: number, amount: number) => {
    if (!token) return;
    setIsNegotiating(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/offers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ amount })
      });
      if (res.ok) {
        toast.success('Offer sent successfully!');
      } else {
        const data = await res.json();
        toast.error(data.error || 'Failed to send offer');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsNegotiating(false);
    }
  };

  const handleSearch = async (query: string) => {
    if (!token) return;
    try {
      const res = await fetch(`/api/pros/search?query=${query}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setSearchResults(await res.json());
      } else {
        toast.error('Search failed');
      }
    } catch (err) {
      console.error('Search failed', err);
      toast.error('Network error during search');
    }
  };

  return {
    jobs,
    pendingJobs,
    searchResults,
    isPostingJob,
    isAcceptingJob,
    isConfirmingMatch,
    isCompletingJob,
    isAcceptingOffer,
    isNegotiating,
    fetchJobs,
    fetchPendingJobs,
    handlePostJob,
    handleAcceptJob,
    handleConfirmMatch,
    handleCompleteJob,
    handleAcceptOffer,
    handleNegotiate,
    handleSearch,
    setSearchResults,
    searchQuery,
    setSearchQuery,
    localOnly,
    setLocalOnly,
    categories
  };
}
