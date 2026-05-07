// FILE: src/components/Skeleton.tsx
// PURPOSE: Skeleton loading placeholders — replaces full-page spinners.
//          Each export matches the layout of the component it stands in for.

import React from 'react';

// Base pulse element
function Bone({ className = '' }: { className?: string }) {
  return <div className={`bg-gray-200 rounded-xl animate-pulse ${className}`} />;
}

/** Skeleton for a single pro search result card */
export function ProCardSkeleton() {
  return (
    <div className="bg-white border border-border rounded-2xl p-4 sm:p-5">
      <div className="flex items-start gap-4">
        <Bone className="w-14 h-14 rounded-full flex-shrink-0" />
        <div className="flex-1 space-y-2">
          <Bone className="h-4 w-1/2" />
          <Bone className="h-3 w-1/3" />
          <Bone className="h-3 w-2/3" />
          <div className="flex gap-2 mt-3">
            <Bone className="h-7 w-20 rounded-full" />
            <Bone className="h-7 w-20 rounded-full" />
          </div>
        </div>
      </div>
    </div>
  );
}

/** Skeleton for the search results list (shows 3 cards) */
export function SearchResultsSkeleton() {
  return (
    <div className="space-y-4">
      {[1, 2, 3].map(i => <ProCardSkeleton key={i} />)}
    </div>
  );
}

/** Skeleton for a single job card */
export function JobCardSkeleton() {
  return (
    <div className="bg-white border border-border rounded-2xl p-4 sm:p-5 space-y-3">
      <div className="flex items-start justify-between">
        <Bone className="h-5 w-1/2" />
        <Bone className="h-6 w-20 rounded-full" />
      </div>
      <Bone className="h-3 w-3/4" />
      <Bone className="h-3 w-1/3" />
    </div>
  );
}

/** Skeleton for the jobs list (shows 4 cards) */
export function JobListSkeleton() {
  return (
    <div className="space-y-4">
      {[1, 2, 3, 4].map(i => <JobCardSkeleton key={i} />)}
    </div>
  );
}

/** Skeleton for the overview stats row */
export function OverviewSkeleton() {
  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[1,2,3,4].map(i => <div key={i}><Bone className="h-20 rounded-2xl" /></div>)}
      </div>
      <div className="space-y-4">
        <Bone className="h-6 w-40" />
        {[1,2].map(i => <div key={i}><JobCardSkeleton /></div>)}
      </div>
    </div>
  );
}

/** Skeleton for the profile page */
export function ProfileSkeleton() {
  return (
    <div className="space-y-8">
      <div className="flex items-start gap-6">
        <Bone className="w-24 h-24 rounded-full flex-shrink-0" />
        <div className="flex-1 space-y-3">
          <Bone className="h-6 w-1/3" />
          <Bone className="h-4 w-1/2" />
          <Bone className="h-4 w-2/3" />
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {[1,2,3,4,5,6].map(i => <div key={i}><Bone className="h-32 rounded-2xl" /></div>)}
      </div>
    </div>
  );
}
