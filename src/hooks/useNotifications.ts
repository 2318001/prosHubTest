// FILE: src/hooks/useNotifications.ts
// PURPOSE: Notifications delivered via WebSocket push (v8+).
//          Falls back to a single REST fetch on mount for history.
//          NEW: Auto-reconnect with exponential backoff on connection loss.
//          No more polling — the WS connection delivers new notifications instantly.

import { useState, useCallback, useEffect, useRef } from 'react';
import { toast } from 'sonner';
import { Notification } from '../types';

export function useNotifications(token: string | null) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  
  const MAX_RETRIES = 5;

  // Fetch notification history on mount (one-time REST call)
  const fetchNotifications = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/notifications', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setNotifications(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch notifications', err);
    }
  }, [token]);

  // Connect to WebSocket with auto-reconnect logic
  const connect = useCallback(() => {
    if (!token) return;
    
    // Don't create duplicate connection
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      console.log('✅ WebSocket already connected');
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('✅ WebSocket connected');
        setIsConnected(true);
        reconnectCountRef.current = 0; // Reset counter on successful connection
        // Authenticate the WebSocket connection with our JWT
        ws.send(JSON.stringify({ type: 'auth', token }));
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          // Push a new notification into the list without a fetch round-trip
          if (msg.type === 'notification') {
            setNotifications(prev => [{
              id: msg.id || String(Date.now()),
              user_id: 0,
              title: msg.notificationType || 'notification',
              content: msg.content,
              type: msg.notificationType,
              is_read: 0,
              created_at: msg.createdAt || new Date().toISOString(),
              job_id: msg.jobId,
            } as Notification, ...prev].slice(0, 50)); // Keep last 50 notifications
          }
        } catch (err) {
          console.error('Failed to parse notification:', err);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      };

      ws.onclose = () => {
        console.log('❌ WebSocket closed, attempting reconnect...');
        setIsConnected(false);
        
        if (reconnectCountRef.current < MAX_RETRIES) {
          // Exponential backoff: 1s, 2s, 4s, 8s, 16s
          const delayMs = Math.pow(2, reconnectCountRef.current) * 1000;
          reconnectCountRef.current++;
          console.log(
            `Reconnecting in ${delayMs / 1000}s (attempt ${reconnectCountRef.current}/${MAX_RETRIES})`
          );
          
          reconnectTimeoutRef.current = setTimeout(connect, delayMs);
        } else {
          console.error('❌ Max reconnect attempts reached');
          toast.error('Connection lost. Please refresh the page.');
        }
      };
    } catch (err) {
      console.error('WebSocket creation failed:', err);
      setIsConnected(false);
    }
  }, [token]);

  // Initial connection on mount
  useEffect(() => {
    connect();
    fetchNotifications();
    
    // Cleanup on unmount
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect, fetchNotifications]);

  const markAsRead = useCallback(async () => {
    if (!token) return;
    try {
      await fetch('/api/notifications/read', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setNotifications(prev => prev.map(n => ({ ...n, is_read: 1 })));
    } catch (err) {
      console.error('Failed to mark notifications as read', err);
    }
  }, [token]);

  return {
    notifications,
    fetchNotifications,
    markAsRead,
    wsRef,
    isConnected,
  };
}
