// FILE: src/components/Dashboard/ProMap.tsx
// PURPOSE: Interactive Leaflet.js map showing search results as pins.
//          Zero API key required — uses OpenStreetMap tiles.
//          Clicking a pin opens the pro's profile card.

import React, { useEffect, useRef } from 'react';
import { User } from '../../types';

interface ProMapProps {
  pros: User[];
  clientLat?: number | null;
  clientLng?: number | null;
  onViewProfile: (pro: User) => void;
}

declare const L: any; // Leaflet loaded via CDN in index.html

export default function ProMap({ pros, clientLat, clientLng, onViewProfile }: ProMapProps) {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<any>(null);

  useEffect(() => {
    // Leaflet must be available globally (loaded in index.html)
    if (!mapContainerRef.current || typeof L === 'undefined') return;
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }

    // Find a reasonable centre: client location, first pro, or UK default
    const centre: [number, number] =
      clientLat && clientLng ? [clientLat, clientLng] :
      pros[0]?.location_lat && pros[0]?.location_lng ? [pros[0].location_lat!, pros[0].location_lng!] :
      [51.5, -0.12];

    const map = L.map(mapContainerRef.current, { zoomControl: true, scrollWheelZoom: false });
    mapRef.current = map;

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 18,
    }).addTo(map);

    // Client location pin (blue)
    if (clientLat && clientLng) {
      const clientIcon = L.divIcon({
        html: `<div style="width:14px;height:14px;background:#2563eb;border:2px solid white;border-radius:50%;box-shadow:0 0 0 3px rgba(37,99,235,0.25);"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7],
        className: '',
      });
      L.marker([clientLat, clientLng], { icon: clientIcon })
        .addTo(map)
        .bindPopup('<strong>You</strong>');
    }

    // Pro pins (green = verified, amber = unverified)
    const prosWithLocation = pros.filter(p => p.location_lat && p.location_lng);
    prosWithLocation.forEach(pro => {
      const isVerified = (pro.is_verified || 0) >= 100;
      const colour = isVerified ? '#16a34a' : '#d97706';
      const proIcon = L.divIcon({
        html: `<div style="width:12px;height:12px;background:${colour};border:2px solid white;border-radius:50%;box-shadow:0 1px 4px rgba(0,0,0,0.3);cursor:pointer;"></div>`,
        iconSize: [12, 12],
        iconAnchor: [6, 6],
        className: '',
      });
      const distText = pro.distance != null ? `<br/><span style="color:#2563eb;font-size:11px;">${pro.distance < 1 ? '<1 km' : Math.round(pro.distance) + ' km'} away</span>` : '';
      const ratingText = pro.avg_rating ? `<br/><span style="color:#d97706;font-size:11px;">★ ${pro.avg_rating}</span>` : '';
      L.marker([pro.location_lat!, pro.location_lng!], { icon: proIcon })
        .addTo(map)
        .bindPopup(`
          <div style="min-width:140px;font-family:sans-serif;">
            <strong style="font-size:13px;">${pro.name}</strong>
            <div style="font-size:11px;color:#666;margin:2px 0;">${(pro.skills || []).slice(0, 2).join(', ') || 'Pro'}</div>
            ${distText}${ratingText}
            <button onclick="window.__proshubViewPro('${pro.id}')" style="margin-top:8px;width:100%;padding:5px 8px;background:#2563eb;color:white;border:none;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">View Profile</button>
          </div>
        `);
    });

    // Expose a global so Leaflet popup buttons can call onViewProfile
    (window as any).__proshubViewPro = (proId: string) => {
      const pro = pros.find(p => p.id === proId);
      if (pro) onViewProfile(pro);
    };

    if (prosWithLocation.length > 0) {
      const allPoints: [number, number][] = prosWithLocation.map(p => [p.location_lat!, p.location_lng!]);
      if (clientLat && clientLng) allPoints.push([clientLat, clientLng]);
      map.fitBounds(L.latLngBounds(allPoints).pad(0.15));
    } else {
      map.setView(centre, 11);
    }

    return () => {
      map.remove();
      mapRef.current = null;
      delete (window as any).__proshubViewPro;
    };
  }, [pros, clientLat, clientLng]);

  const prosWithLocation = pros.filter(p => p.location_lat && p.location_lng);

  if (prosWithLocation.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 bg-paper rounded-2xl border-2 border-dashed border-border text-muted text-sm font-medium">
        No pros with location data to show on map
      </div>
    );
  }

  return (
    <div className="rounded-2xl overflow-hidden border border-border" style={{ height: 340 }}>
      <div ref={mapContainerRef} style={{ height: '100%', width: '100%' }} />
    </div>
  );
}
