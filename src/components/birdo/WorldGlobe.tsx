/**
 * WorldGlobe — full-bleed rotating 3D globe with server markers, mirroring
 * mobile's `WorldGlobe.kt`. Uses react-globe.gl (three.js under the hood).
 *
 * Visual goals (matching the mobile spec):
 *  - Solid dark backdrop (#050507) so the globe blends with the app bg
 *  - Soft violet land tint, translucent water, dotted continents
 *  - Brand-purple server points; the selected/connected one glows green
 *  - Auto-rotate when not connected; settles on the active server when connected
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import Globe from 'react-globe.gl';
import type { GlobeMethods } from 'react-globe.gl';
import earthTextureUrl from '../../../node_modules/three-globe/example/img/earth-blue-marble.jpg?url';
import earthTopologyUrl from '../../../node_modules/three-globe/example/img/earth-topology.png?url';
import { brand, status, surface } from '@/lib/birdo-theme';
import { countryCoords } from '@/utils/country-coords';
import type { Server } from '@/store/app-store';

interface PointDatum {
  id: string;
  lat: number;
  lng: number;
  color: string;
  size: number;
  altitude: number;
  isSelected: boolean;
}

export interface WorldGlobeProps {
  servers: Server[];
  selectedServerId?: string | null;
  isConnected?: boolean;
  autoRotate?: boolean;
  className?: string;
}

export function WorldGlobe({
  servers,
  selectedServerId,
  isConnected = false,
  autoRotate = true,
  className = '',
}: WorldGlobeProps) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const cameraReadyRef = useRef(false);
  const [size, setSize] = useState({ w: 380, h: 640 });

  // ── Resize observer (Tauri window is fixed but be safe) ─────────────
  useEffect(() => {
    if (!containerRef.current) return;
    const el = containerRef.current;
    const ro = new ResizeObserver(() => {
      setSize({ w: el.clientWidth, h: el.clientHeight });
    });
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  // ── Configure auto-rotation + initial camera ────────────────────────
  useEffect(() => {
    const g = globeRef.current;
    if (!g) return;
    const controls = g.controls() as unknown as {
      autoRotate: boolean;
      autoRotateSpeed: number;
      enableZoom: boolean;
      enablePan: boolean;
      enableDamping: boolean;
      minPolarAngle: number;
      maxPolarAngle: number;
    };
    controls.autoRotate = autoRotate && !isConnected;
    controls.autoRotateSpeed = 0.28;
    controls.enableZoom = false;
    controls.enablePan = false;
    controls.enableDamping = true;
    controls.minPolarAngle = Math.PI * 0.47;
    controls.maxPolarAngle = Math.PI * 0.53;

    if (!cameraReadyRef.current) {
      g.pointOfView({ lat: 12, lng: -20, altitude: 2.35 }, 0);
      cameraReadyRef.current = true;
    }
  }, [autoRotate, isConnected]);

  // ── Pan to selected server when connected ───────────────────────────
  useEffect(() => {
    if (!isConnected || !selectedServerId || !globeRef.current) return;
    const sel = servers.find((s) => s.id === selectedServerId);
    if (!sel) return;
    const coords = countryCoords(sel.countryCode);
    if (!coords) return;
    globeRef.current.pointOfView({ lat: coords[0], lng: coords[1], altitude: 2.2 }, 1500);
  }, [isConnected, selectedServerId, servers]);

  // ── Build point data from servers ───────────────────────────────────
  const points = useMemo<PointDatum[]>(() => {
    const seen = new Set<string>();
    const out: PointDatum[] = [];
    for (const srv of servers) {
      const coords = countryCoords(srv.countryCode);
      if (!coords) continue;
      // Dedupe by country (one dot per country, larger if selected lives there)
      const key = srv.countryCode.toUpperCase();
      if (seen.has(key) && srv.id !== selectedServerId) continue;
      seen.add(key);
      const isSelected = srv.id === selectedServerId;
      out.push({
        id: srv.id,
        lat: coords[0],
        lng: coords[1],
        color: isSelected ? (isConnected ? status.green : brand.purple) : brand.purple,
        size: isSelected ? 0.9 : 0.45,
        altitude: isSelected ? 0.02 : 0.005,
        isSelected,
      });
    }
    return out;
  }, [servers, selectedServerId, isConnected]);

  // ── Optional rings under the selected point ─────────────────────────
  const rings = useMemo(() => {
    const sel = points.find((p) => p.isSelected);
    if (!sel) return [];
    return [
      {
        lat: sel.lat,
        lng: sel.lng,
        maxR: 6,
        propagationSpeed: 2,
        repeatPeriod: 1500,
        color: isConnected ? status.green : brand.purple,
      },
    ];
  }, [points, isConnected]);

  return (
    <div
      ref={containerRef}
      className={`absolute inset-0 ${className}`}
      style={{ backgroundColor: surface.s0 }}
      aria-hidden
    >
      <Globe
        ref={globeRef as never}
        width={size.w}
        height={size.h}
        backgroundColor="rgba(0,0,0,0)"
        showGlobe
        globeImageUrl={earthTextureUrl}
        bumpImageUrl={earthTopologyUrl}
        showAtmosphere
        atmosphereColor="#7BB2E6"
        atmosphereAltitude={0.16}
        // Server points
        pointsData={points}
        pointLat="lat"
        pointLng="lng"
        pointColor="color"
        pointAltitude="altitude"
        pointRadius="size"
        pointResolution={6}
        // Pulsing rings under the selected server
        ringsData={rings}
        ringColor={(d: object) => (d as { color: string }).color}
        ringMaxRadius="maxR"
        ringPropagationSpeed="propagationSpeed"
        ringRepeatPeriod="repeatPeriod"
      />
    </div>
  );
}
