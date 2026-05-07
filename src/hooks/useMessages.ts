// FILE: src/hooks/useMessages.ts — Custom hook for job chat. Exposes fetchMessages(jobId) and handleSendMessage(jobId, content).

import { useState, useCallback } from 'react';
import { toast } from 'sonner';
import { Message } from '../types';

export function useMessages(token: string | null) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isSendingMessage, setIsSendingMessage] = useState(false);

  const fetchMessages = useCallback(async (jobId: number) => {
    if (!token) return;
    try {
      const res = await fetch(`/api/jobs/${jobId}/messages`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setMessages(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch messages', err);
    }
  }, [token]);

  const handleSendMessage = async (jobId: number, content: string) => {
    if (!token || !content.trim()) return;
    setIsSendingMessage(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ content })
      });
      if (res.ok) {
        const data = await res.json();
        setMessages(prev => [...prev, data]);
        return true;
      } else {
        toast.error('Failed to send message');
        return false;
      }
    } catch (err) {
      toast.error('Network error. Please try again.');
      return false;
    } finally {
      setIsSendingMessage(false);
    }
  };

  return {
    messages,
    setMessages,
    isSendingMessage,
    fetchMessages,
    handleSendMessage
  };
}
