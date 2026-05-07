// FILE: src/AuthContext.tsx — Global auth state via React Context + localStorage. Provides user, token, login(), logout(), updateUser() to any component via useAuth().
// v8+: Stores refreshToken and silently refreshes accessToken before it expires.

import React, { createContext, useContext, useState, useEffect, useRef } from 'react';

/**
 * USER INTERFACE
 * Defines what a "User" object looks like in our app.
 */
interface User {
  id: string;  // Fixed: Changed from number to string to match Firebase and types.ts
  email: string;
  name: string;
  role: 'client' | 'pro';
  is_admin?: number;
  bio?: string;
  avatar?: string;
  skills?: string[];
  is_verified?: number;
  is_available?: number;
  subscription_status?: 'none' | 'trial' | 'active' | 'expired';
  trial_ends_at?: string | null;
  subscription_ends_at?: string | null;
  location?: string;
}

/**
 * AUTH CONTEXT TYPE
 * Defines the functions and data that will be available to the whole app.
 */
interface AuthContextType {
  user: User | null; // The currently logged-in user's info
  token: string | null; // The access token (JWT, 15-min expiry)
  login: (token: string, user: User, refreshToken?: string) => void; // Function to log in
  logout: () => void; // Function to log out
  updateUser: (user: User) => void; // Function to update user info
  isAuthenticated: boolean; // true if the user is logged in
}

// Create the context (a global storage for auth state)
const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * AUTH PROVIDER
 * This component wraps the entire app. It manages the login state and
 * makes sure the user stays logged in even if they refresh the page.
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const savedUser = localStorage.getItem('user');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('token');
  });
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /**
   * Silently refresh the access token using the stored refresh token.
   * Called ~1 min before expiry by a timer set in login().
   */
  const scheduleRefresh = (accessToken: string) => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    try {
      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      const expiresInMs = payload.exp * 1000 - Date.now();
      const refreshAt = Math.max(expiresInMs - 60_000, 0); // 1 min before expiry
      refreshTimerRef.current = setTimeout(async () => {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) return;
        try {
          const res = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken }),
          });
          if (res.ok) {
            const data = await res.json();
            setToken(data.accessToken);
            localStorage.setItem('token', data.accessToken);
            scheduleRefresh(data.accessToken);
          } else {
            // Refresh token expired — force logout
            setToken(null); setUser(null);
            localStorage.removeItem('token'); localStorage.removeItem('user'); localStorage.removeItem('refreshToken');
          }
        } catch { /* network error — will retry on next load */ }
      }, refreshAt);
    } catch { /* malformed token — ignore */ }
  };

  /**
   * ON LOAD: Validate that a stored token is still structurally valid.
   * We do a lightweight JWT payload check (no secret needed client-side)
   * to clear tokens that have obviously expired by their `exp` claim.
   */
  useEffect(() => {
    if (!token) return;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        // Token has expired — force a clean logout
        setToken(null);
        setUser(null);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('refreshToken');
      } else {
        scheduleRefresh(token);
      }
    } catch {
      // Malformed token — clear it
      setToken(null);
      setUser(null);
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('refreshToken');
    }
  }, []);

  /**
   * LOGIN FUNCTION
   * Saves the token and user info to both the app state and the browser's memory.
   */
  const login = (newToken: string, newUser: User, refreshToken?: string) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(newUser));
    if (refreshToken) localStorage.setItem('refreshToken', refreshToken);
    scheduleRefresh(newToken);
  };

  /**
   * UPDATE USER FUNCTION
   * Updates the user info in both the app state and the browser's memory.
   */
  const updateUser = (newUser: User) => {
    setUser(newUser);
    localStorage.setItem('user', JSON.stringify(newUser));
  };

  /**
   * LOGOUT FUNCTION
   * Clears everything so the user is no longer logged in.
   */
  const logout = () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('refreshToken');
  };

  return (
    /* We provide the state and functions to all child components */
    <AuthContext.Provider value={{ user, token, login, logout, updateUser, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * USE AUTH HOOK
 * A shortcut for components to access the auth state.
 * Usage: const { user, logout } = useAuth();
 */
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
