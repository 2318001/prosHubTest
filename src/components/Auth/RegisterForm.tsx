// FILE: src/components/Auth/RegisterForm.tsx — New user sign-up form: name, email, password, role (client/pro), specialty, and location.

import React from 'react';
import { motion } from 'motion/react';

interface RegisterFormProps {
  name: string;
  setName: (val: string) => void;
  email: string;
  setEmail: (val: string) => void;
  password: string;
  setPassword: (val: string) => void;
  role: 'client' | 'pro';
  setRole: (val: 'client' | 'pro') => void;
  selectedCategory: string;
  setSelectedCategory: (val: string) => void;
  location: string;
  setLocation: (val: string) => void;
}

/**
 * REGISTER FORM SUB-COMPONENT
 * Handles the registration inputs, including role selection (Client vs Pro)
 * and specialty selection for professionals.
 */
export default function RegisterForm({ 
  name, setName, email, setEmail, password, setPassword, 
  role, setRole, selectedCategory, setSelectedCategory,
  location, setLocation
}: RegisterFormProps) {
  return (
    <>
      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Full Name</label>
        <input 
          type="text" required 
          placeholder="John Doe"
          className="input-brutal"
          value={name} onChange={e => setName(e.target.value)}
        />
      </div>
      
      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Email Address</label>
        <input 
          type="email" required 
          placeholder="name@example.com"
          className="input-brutal"
          value={email} onChange={e => setEmail(e.target.value)}
        />
      </div>
      
      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Password</label>
        <input 
          type="password" required 
          placeholder="••••••••"
          className="input-brutal"
          value={password} onChange={e => setPassword(e.target.value)}
        />
      </div>

      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Location (City/Region)</label>
        <input 
          type="text" required 
          placeholder="e.g. London, Manchester"
          className="input-brutal"
          value={location} onChange={e => setLocation(e.target.value)}
        />
      </div>

      <div>
        <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-2">I am a...</label>
        <div className="grid grid-cols-2 gap-3">
          <button 
            type="button"
            onClick={() => setRole('client')}
            className={`p-3 rounded-xl border-2 font-bold transition-all ${role === 'client' ? 'border-blue-primary bg-blue-light text-blue-primary' : 'border-border bg-paper text-muted'}`}
          >
            Client
          </button>
          <button 
            type="button"
            onClick={() => setRole('pro')}
            className={`p-3 rounded-xl border-2 font-bold transition-all ${role === 'pro' ? 'border-blue-primary bg-blue-light text-blue-primary' : 'border-border bg-paper text-muted'}`}
          >
            Professional
          </button>
        </div>
      </div>

      {role === 'pro' && (
        <motion.div 
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="space-y-1"
        >
          <label className="block text-xs font-bold uppercase tracking-wider text-muted mb-1">Your Specialty / Primary Skill</label>
          <input 
            type="text"
            required
            list="categories-list"
            placeholder="e.g. Logo Design, Yoga Instructor, Plumber"
            className="input-brutal"
            value={selectedCategory}
            onChange={e => setSelectedCategory(e.target.value)}
          />
          <datalist id="categories-list">
            <option value="Plumbing" />
            <option value="Electrical" />
            <option value="Cleaning" />
            <option value="Gardening" />
            <option value="Handyman" />
            <option value="Painting" />
            <option value="IT & Tech" />
            <option value="Tutoring" />
            <option value="Moving" />
            <option value="Marketing" />
            <option value="Legal" />
            <option value="Fitness" />
            <option value="Graphic Design" />
            <option value="Mobile App Development" />
          </datalist>
        </motion.div>
      )}
    </>
  );
}
