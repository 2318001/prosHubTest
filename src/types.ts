// FILE: src/types.ts — Shared TypeScript interfaces (v8: added acceptance_rate, avg_response_minutes, dispute fields)

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'client' | 'pro';
  is_admin?: number;
  bio?: string;
  avatar?: string;
  skills?: string[];
  is_verified?: number;
  is_available?: number;
  location?: string;
  location_lat?: number | null;
  location_lng?: number | null;
  portfolio?: PortfolioItem[];
  reviews?: Review[];
  documents?: Document[];
  work_history?: Job[];
  distance?: number | null;
  avg_rating?: number | null;
  review_count?: number;
  /** Percentage of job offers the pro has accepted (0–100) */
  acceptance_rate?: number | null;
  /** Average minutes between job post and pro's first response */
  avg_response_minutes?: number | null;
  subscription_status?: 'none' | 'trial' | 'active' | 'expired';
  trial_ends_at?: string | null;
  subscription_ends_at?: string | null;
  rejection_reason?: string | null;
}

export type JobStatus =
  | 'pending'
  | 'matching'
  | 'negotiating'
  | 'accepted'
  | 'active'
  | 'pro_done'
  | 'finalized'
  | 'cancelled'
  | 'disputed';

export interface Job {
  id: string;
  client_id: string;
  pro_id: string | null;
  title: string;
  description: string;
  price?: number;
  location: string;
  category: string;
  status: JobStatus;
  file_url?: string;
  image_url?: string;
  created_at: string;
  lat?: number;
  lng?: number;
  client_name?: string;
  pro_name?: string;
  match_confirmed_client?: number;
  match_confirmed_pro?: number;
  match_expires_at?: string | null;
  final_price?: number | null;
  initial_price?: number;
  pro_distance?: number;
  estimated_time?: number;
  pro_verified?: number;
  client_verified?: number;
  required_skills?: string[];
  can_cancel?: number;
  /** Dispute fields */
  dispute_reason?: string;
  dispute_raised_by?: string;
  dispute_at?: string;
  dispute_resolution?: string;
  dispute_resolved_at?: string;
}

export interface Message {
  id: string;
  job_id: string;
  sender_id: string;
  content: string;
  created_at: string;
  sender_name?: string;
}

export interface Offer {
  id: string;
  job_id: string;
  pro_id: string;
  amount: number;
  status: 'pending' | 'accepted' | 'rejected';
  created_at: string;
  pro_name?: string;
  sender_name?: string;
}

export interface Notification {
  id: string;
  user_id: number;
  title: string;
  content: string;
  type: string;
  is_read: number;
  created_at: string;
  job_id?: string;
  action_id?: string;
}

export interface Review {
  id: string;
  job_id: string;
  reviewer_id: string;
  reviewee_id: string;
  rating: number;
  comment: string;
  is_private: number;
  created_at: string;
  reviewer_name?: string;
  client_name?: string;
}

export interface Document {
  id: string;
  user_id: string;
  title: string;
  file_url: string;
  created_at: string;
}

export interface PortfolioItem {
  id: string;
  pro_id: string;
  title: string;
  description: string;
  image_url: string;
  video_url?: string;
  doc_url?: string;
  type?: 'image' | 'video' | 'document';
  created_at: string;
}
