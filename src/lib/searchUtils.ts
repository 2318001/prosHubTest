// =============================================================================
// File: src/lib/searchUtils.ts
// Purpose: Frontend search utilities, keyword matching, and API integration
// =============================================================================

export interface SearchResult {
  id: string;
  name: string;
  skills: string[];
  location: string;
  location_lat?: number;
  location_lng?: number;
  bio?: string;
  avatar?: string;
  rating?: number;
  distance?: number | null;
  score: number;
  is_available: boolean;
  is_verified: boolean;
  total_jobs?: number;
  response_time?: number | null;
}

export interface MatchResult {
  skills: string[];
  score: number;
  matchedKeywords: string[];
}

// Comprehensive skill-to-keyword mapping
export const SKILL_KEYWORDS: Record<string, string[]> = {
  Plumbing: [
    "leak", "leaking", "water leak", "pipe", "drain", "drain cleaning", "toilet", "faucet", "sink",
    "water heater", "shower", "bath", "tap", "blockage", "clog", "plumber", "heating", "radiator",
    "burst pipe", "leaking tap", "toilet repair", "sewage", "pipe burst", "emergency plumbing",
  ],
  Electrical: [
    "wiring", "rewiring", "socket", "light", "switch", "fuse", "circuit", "breaker", "installation",
    "electrician", "electricity", "alarm", "cctv", "power", "volt", "amp", "lighting", "fault",
    "trip", "electric", "rewiring", "electrical installation", "surge protection", "power outlet",
  ],
  Cleaning: [
    "house", "office", "carpet", "carpet cleaning", "window", "deep clean", "vacuum", "mopping",
    "dusting", "laundry", "cleaner", "ironing", "end of tenancy", "spring clean", "post construction",
    "sanitize", "scrub", "spotless", "pressure wash", "house cleaning", "office cleaning",
  ],
  Gardening: [
    "lawn", "lawn care", "mowing", "weeding", "planting", "trimming", "hedge", "garden",
    "landscaping", "grass", "gardener", "tree", "fencing", "pruning", "soil", "maintenance",
    "yard work", "garden maintenance", "hedge trimming", "tree cutting", "garden design",
  ],
  Handyman: [
    "furniture", "assembly", "mounting", "shelf", "door", "lock", "fixing", "repair", "hanging",
    "handyman", "flatpack", "curtain", "installation", "small repairs", "maintenance", "hanging pictures",
    "fitting shelves", "door repair", "cabinet installation", "general repairs",
  ],
  Painting: [
    "wall", "ceiling", "decorating", "wallpaper", "exterior", "interior", "paint", "varnish",
    "painter", "plastering", "color", "finish", "renovation", "decor", "house painting", "interior design",
    "exterior painting", "commercial painting", "decorating service",
  ],
  "IT & Tech": [
    "computer", "laptop", "software", "network", "wifi", "coding", "website", "tech support", "it",
    "developer", "programming", "app", "website design", "data", "security", "troubleshooting", "repair",
    "installation", "setup", "technical support", "virus removal", "web development",
  ],
  Tutoring: [
    "math", "science", "english", "exam", "lesson", "teacher", "study", "homework", "tutor",
    "language", "music", "education", "learning", "coaching", "private lessons", "test prep", "ielts",
    "gcse", "a-level", "university", "online tutoring",
  ],
  Moving: [
    "packing", "delivery", "van", "transport", "furniture moving", "relocation", "heavy lifting",
    "mover", "courier", "removals", "shipping", "moving service", "house move", "office relocation",
    "storage", "man and van",
  ],
  Marketing: [
    "seo", "social media", "ads", "advertising", "branding", "content", "strategy", "copywriting",
    "digital marketing", "campaign", "promotion", "marketing strategy", "social media marketing",
    "content marketing", "email marketing", "google ads", "facebook ads",
  ],
  Legal: [
    "contract", "advice", "lawyer", "solicitor", "notary", "dispute", "litigation", "property law",
    "legal", "counsel", "legal advice", "contract review", "legal consultation", "conveyancing",
  ],
  Fitness: [
    "yoga", "personal trainer", "gym", "workout", "nutrition", "pilates", "coach", "training",
    "fitness", "exercise", "wellness", "personal training", "fitness coaching", "gym training",
    "nutrition coaching", "weight loss",
  ],
};

// Reverse mapping: keywords to skills
export function getSkillForKeyword(keyword: string): string | null {
  const q = keyword.toLowerCase().trim();

  for (const [skill, keywords] of Object.entries(SKILL_KEYWORDS)) {
    if (skill.toLowerCase() === q) return skill;

    for (const kw of keywords) {
      if (kw === q) return skill;
      if (kw.includes(q) || q.includes(kw)) return skill;
    }
  }

  return null;
}

// Find matching skills for a search query
export function matchQuery(query: string): MatchResult {
  const q = query.toLowerCase().trim();

  if (!q) {
    return { skills: [], score: 0, matchedKeywords: [] };
  }

  const matches: { skill: string; score: number; keyword: string }[] = [];

  for (const [skill, keywords] of Object.entries(SKILL_KEYWORDS)) {
    // Exact skill match
    if (skill.toLowerCase() === q) {
      matches.push({ skill, score: 100, keyword: skill });
      continue;
    }

    // Keyword matching
    for (const keyword of keywords) {
      let score = 0;

      // Exact keyword match
      if (keyword === q) {
        score = 100;
      }
      // Keyword contains query
      else if (keyword.includes(q)) {
        score = 80;
      }
      // Query contains keyword
      else if (q.includes(keyword)) {
        score = 60;
      }
      // Partial word match
      else if (keyword.split(" ").some((word) => word === q || word.includes(q.split(" ")[0]))) {
        score = 30;
      }

      if (score > 0) {
        matches.push({ skill, score, keyword });
      }
    }
  }

  // Sort by score and get unique skills
  const uniqueMatches = matches.sort((a, b) => b.score - a.score);
  const skillMap = new Map<string, number>();

  for (const match of uniqueMatches) {
    if (!skillMap.has(match.skill)) {
      skillMap.set(match.skill, match.score);
    }
  }

  const topSkills = Array.from(skillMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([skill]) => skill);

  const matchedKeywords = uniqueMatches
    .filter((m) => topSkills.includes(m.skill))
    .map((m) => m.keyword);

  const avgScore = topSkills.length > 0 ? Array.from(skillMap.values()).reduce((a, b) => a + b, 0) / topSkills.length : 0;

  return {
    skills: topSkills,
    score: Math.round(avgScore),
    matchedKeywords: [...new Set(matchedKeywords)],
  };
}

// Calculate distance in km using Haversine formula
export function calculateDistance(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLng = ((lng2 - lng1) * Math.PI) / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return parseFloat((R * c).toFixed(1));
}

// Format distance for display
export function formatDistance(km: number | null): string {
  if (km === null || km === undefined) return "Unknown distance";
  if (km < 1) return "< 1 km away";
  if (km < 1000) return `${km} km away`;
  return "Far away";
}

// Get location from geolocation API
export async function getUserLocation(): Promise<{ lat: number; lng: number } | null> {
  return new Promise((resolve) => {
    if (!navigator.geolocation) {
      resolve(null);
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          lat: position.coords.latitude,
          lng: position.coords.longitude,
        });
      },
      () => {
        resolve(null);
      }
    );
  });
}

// API call: Search professionals
export async function searchPros(
  query: string,
  token: string,
  localOnly: boolean = false,
  userLat?: number,
  userLng?: number
): Promise<SearchResult[]> {
  const params = new URLSearchParams({
    query,
    localOnly: localOnly.toString(),
  });

  if (userLat !== undefined && userLng !== undefined) {
    params.append("lat", userLat.toString());
    params.append("lng", userLng.toString());
  }

  const response = await fetch(`/api/pros/search?${params}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error("Search failed");
  }

  return response.json();
}

// API call: Get pro profile
export async function getProProfile(proId: string, token: string): Promise<SearchResult | null> {
  const response = await fetch(`/api/pros/${proId}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    return null;
  }

  return response.json();
}

// Format pro profile for display
export function formatProProfile(pro: SearchResult): { title: string; subtitle: string } {
  const parts: string[] = [];

  if (pro.rating && pro.rating > 0) {
    parts.push(`⭐ ${pro.rating.toFixed(1)}`);
  }

  if (pro.total_jobs && pro.total_jobs > 0) {
    parts.push(`${pro.total_jobs} jobs`);
  }

  if (pro.response_time !== null && pro.response_time !== undefined) {
    parts.push(`${pro.response_time}h response`);
  }

  if (pro.distance !== null && pro.distance !== undefined) {
    parts.push(formatDistance(pro.distance));
  }

  return {
    title: pro.name,
    subtitle: parts.join(" • "),
  };
}

// Suggest similar professionals based on skills
export function suggestSimilarSkills(skill: string): string[] {
  const similar: string[] = [];

  const skillKeywords = SKILL_KEYWORDS[skill] || [];

  for (const [otherSkill, keywords] of Object.entries(SKILL_KEYWORDS)) {
    if (otherSkill === skill) continue;

    // Check if keywords overlap
    const overlap = skillKeywords.filter((k) => keywords.includes(k)).length;
    if (overlap > 0) {
      similar.push(otherSkill);
    }
  }

  return similar.slice(0, 3);
}

// Get all skill categories
export function getAllSkills(): string[] {
  return Object.keys(SKILL_KEYWORDS);
}

// Validate professional profile completeness
export function validateProProfile(pro: any): { isComplete: boolean; missingFields: string[] } {
  const required = ["name", "email", "skills", "location", "bio"];
  const missing = required.filter((field) => !pro[field] || (Array.isArray(pro[field]) && pro[field].length === 0));

  return {
    isComplete: missing.length === 0,
    missingFields: missing,
  };
}

// Get search suggestions based on popular queries
export function getSearchSuggestions(partial: string): string[] {
  const q = partial.toLowerCase().trim();

  if (!q) {
    return getAllSkills();
  }

  const matches: string[] = [];

  // Add exact skill matches
  for (const skill of getAllSkills()) {
    if (skill.toLowerCase().includes(q)) {
      matches.push(skill);
    }
  }

  // Add keyword matches
  for (const [skill, keywords] of Object.entries(SKILL_KEYWORDS)) {
    for (const keyword of keywords) {
      if (keyword.includes(q) && !matches.includes(skill)) {
        matches.push(skill);
      }
    }
  }

  return matches.slice(0, 10);
}

// Export all as single object for convenience
export const SearchUtils = {
  matchQuery,
  getSkillForKeyword,
  calculateDistance,
  formatDistance,
  getUserLocation,
  searchPros,
  getProProfile,
  formatProProfile,
  suggestSimilarSkills,
  getAllSkills,
  validateProProfile,
  getSearchSuggestions,
};

export default SearchUtils;
