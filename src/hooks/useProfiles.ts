// FILE: src/hooks/useProfiles.ts — Custom hook for profile, document, and portfolio management (save, upload, delete).

import React, { useState, useCallback } from 'react';
import { toast } from 'sonner';
import { User, PortfolioItem, Document } from '../types';

export function useProfile(token: string | null, user: User | null, updateUser: (user: User) => void) {
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [isSavingAvatar, setIsSavingAvatar] = useState(false);
  const [isPublicProfile, setIsPublicProfile] = useState(true);
  const [isPublicDocs, setIsPublicDocs] = useState(false);
  const [userDocuments, setUserDocuments] = useState<Document[]>([]);
  const [completedWorks, setCompletedWorks] = useState<PortfolioItem[]>([]);

  const fetchProfile = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/user/profile', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        updateUser(data);
        setIsPublicProfile(data.is_public_profile === 1);
        setIsPublicDocs(data.is_public_docs === 1);
      }
    } catch (err) {
      console.error('Failed to fetch profile', err);
    }
  }, [token, updateUser]);

  const fetchUserDocuments = useCallback(async () => {
    if (!token || user?.role !== 'pro') return;
    try {
      const res = await fetch('/api/user/documents', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setUserDocuments(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch documents', err);
    }
  }, [token, user?.role]);

  const fetchCompletedWorks = useCallback(async () => {
    if (!token || user?.role !== 'pro') return;
    try {
      const res = await fetch('/api/user/completed-works', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setCompletedWorks(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch portfolio', err);
    }
  }, [token, user?.role]);

  const handleSaveProfile = async (profileData: any) => {
    if (!token) return;
    setIsSavingProfile(true);
    try {
      const res = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(profileData)
      });
      if (res.ok) {
        toast.success('Profile updated successfully!');
        fetchProfile();
        return true;
      } else {
        toast.error('Failed to update profile');
        return false;
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
      return false;
    } finally {
      setIsSavingProfile(false);
    }
  };

  const handleToggleVisibility = async (type: 'profile' | 'docs', value: boolean) => {
    if (!token || !user) return;
    try {
      const res = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          name: user.name,
          bio: user.bio,
          location: user.location,
          skills: user.skills,
          avatar: user.avatar,
          is_public_profile: type === 'profile' ? value : isPublicProfile,
          is_public_docs: type === 'docs' ? value : isPublicDocs
        })
      });
      if (res.ok) {
        if (type === 'profile') setIsPublicProfile(value);
        else setIsPublicDocs(value);
        fetchProfile();
      }
    } catch (err) {
      toast.error('Failed to update visibility');
    }
  };

  const handleUploadDocument = async (title: string, url: string) => {
    if (!token) return;
    try {
      const res = await fetch('/api/user/documents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ title, file_url: url })
      });
      if (res.ok) fetchUserDocuments();
    } catch (err) {
      toast.error('Failed to upload document');
    }
  };

  const handleDeleteDocument = async (id: number) => {
    if (!token) return;
    try {
      const res = await fetch(`/api/user/documents/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) fetchUserDocuments();
    } catch (err) {
      toast.error('Failed to delete document');
    }
  };

  const handleAddWork = async (workData: any) => {
    if (!token) return;
    try {
      const res = await fetch('/api/user/completed-works', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(workData)
      });
      if (res.ok) {
        toast.success('Work added to portfolio!');
        fetchCompletedWorks();
        return true;
      } else {
        toast.error('Failed to add work');
        return false;
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
      return false;
    }
  };

  const [isVerifying, setIsVerifying] = useState(false);

  const handleVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setIsVerifying(true);
    try {
      const res = await fetch('/api/user/verify', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success('Verification submitted successfully!');
        fetchProfile();
      } else {
        toast.error('Failed to submit verification');
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };

  return {
    isSavingProfile,
    isSavingAvatar,
    isPublicProfile,
    isPublicDocs,
    isVerifying,
    userDocuments,
    completedWorks,
    fetchProfile,
    fetchUserDocuments,
    fetchCompletedWorks,
    handleSaveProfile,
    handleToggleVisibility,
    handleUploadDocument,
    handleDeleteDocument,
    handleAddWork,
    handleVerification,
    setIsSavingAvatar
  };
}
