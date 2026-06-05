/**
 * WorldGlobe — a spinning Earth rendered with pure DOM/CSS/SVG (NO <canvas>).
 *
 * The previous canvas globe produced vertical texture-atlas banding under
 * WebView2 that survived every fix (alpha flags, removing backdrop blurs,
 * disabling GPU). This implementation eliminates the canvas entirely:
 *
 *  - Continents come from the same Natural Earth 110m TopoJSON, but are
 *    projected ONCE (equirectangular) into a single SVG <path> data-URI at
 *    module load — string math, no per-frame raster.
 *  - That map is the background of a 200%-wide element holding two copies side
 *    by side; a CSS `transform: translateX(0 → -50%)` keyframe scrolls it for a
 *    seamless rotation. CSS transforms are the one animation path WebView2
 *    composites cleanly, so there is no banding.
 *  - A circular clip + radial shading + atmosphere ring sell the 3D sphere.
 *
 * It is a presentational background only (reads `isConnected` to tint the
 * atmosphere green vs purple); it never calls invoke(). Server dots and the
 * connection arc from the old canvas globe are intentionally dropped — the
 * connection state is already conveyed by the StatusPill + connect button.
 */
import { useMemo } from 'react';
import { feature } from 'topojson-client';
import worldData from 'world-atlas/countries-110m.json';
import type { Feature, FeatureCollection, GeometryObject } from 'geojson';
import { brand } from '@/lib/birdo-theme';
import { countryCoords } from '@/utils/country-coords';
import type { Server } from '@/store/app-store';

export interface WorldGlobeProps {
  servers: Server[];
  selectedServerId?: string | null;
  isConnected?: boolean;
  autoRotate?: boolean;
  className?: string;
}

/**
 * Build one equirectangular SVG path (viewBox 0 0 360 180) covering every
 * country polygon. lon,lat → x=lon+180, y=90-lat. Subpaths break on an
 * antimeridian wrap (|Δx| > 180) so a coastline crossing ±180° doesn't draw a
 * horizontal streak across the map. Runs once at module load.
 */
function buildWorldPath(): string {
  // Cast through unknown — the world-atlas JSON module isn't strongly typed and
  // topojson-client's feature() overloads don't line up with the import shape.
  const topo = worldData as unknown as {
    objects: { countries: GeometryObject };
  };
  const fc = feature(
    worldData as never,
    topo.objects.countries as never,
  ) as unknown as FeatureCollection<GeometryObject>;

  const parts: string[] = [];
  const addRing = (ring: number[][]) => {
    if (ring.length < 3) return;
    let d = '';
    let prevX = 0;
    for (let i = 0; i < ring.length; i++) {
      const x = ring[i][0] + 180;
      const y = 90 - ring[i][1];
      if (i === 0 || Math.abs(x - prevX) > 180) {
        d += `M${x.toFixed(2)} ${y.toFixed(2)}`;
      } else {
        d += `L${x.toFixed(2)} ${y.toFixed(2)}`;
      }
      prevX = x;
    }
    parts.push(d + 'Z');
  };

  for (const f of fc.features as Feature<GeometryObject>[]) {
    const g = f.geometry;
    if (g.type === 'Polygon') {
      for (const ring of g.coordinates as number[][][]) addRing(ring);
    } else if (g.type === 'MultiPolygon') {
      for (const poly of g.coordinates as number[][][][])
        for (const ring of poly) addRing(ring);
    }
  }
  return parts.join('');
}

const WORLD_PATH = buildWorldPath();

/** Equirectangular world map as an SVG data-URI for use as a CSS background. */
function worldMapUrl(landColor: string): string {
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 360 180' preserveAspectRatio='none'>` +
    `<path d='${WORLD_PATH}' fill='${landColor}'/></svg>`;
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

export function WorldGlobe({
  servers,
  selectedServerId = null,
  isConnected = false,
  autoRotate = true,
  className = '',
}: WorldGlobeProps) {
  const mapUrl = useMemo(() => worldMapUrl('rgba(95,168,224,0.62)'), []);

  const atmo = isConnected
    ? 'rgba(68, 209, 126, 0.22)' // green when connected
    : 'rgba(73, 131, 199, 0.20)'; // brand blue idle
  const dotColor = isConnected ? '#44D17E' : brand.purple;

  // Unique server locations → offsets within ONE map tile (0..50% of the
  // 400%-wide scroller). Rendered twice (tile 0 and +50%) so a marker stays on
  // screen through the seamless scroll. Deduped by rounded lat/lon.
  const dots = useMemo(() => {
    const seen = new Set<string>();
    const out: { key: string; left: number; top: number; selected: boolean }[] = [];
    for (const s of servers) {
      const ll = countryCoords(s.countryCode);
      if (!ll) continue;
      const [lat, lon] = ll;
      const k = `${lat.toFixed(1)},${lon.toFixed(1)}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({
        key: k,
        left: ((lon + 180) / 360) * 50, // % within the scroller (one tile = 50%)
        top: ((90 - lat) / 180) * 100,
        selected: s.id === selectedServerId,
      });
    }
    return out;
  }, [servers, selectedServerId]);

  const playState = autoRotate ? 'running' : 'paused';

  return (
    <div className={`birdo-globe-wrap ${className}`} aria-hidden>
      <div className="birdo-globe">
        <div
          className="birdo-globe__map"
          style={{ backgroundImage: `url("${mapUrl}")`, animationPlayState: playState }}
        />
        <div
          className="birdo-globe__dots"
          style={{ animationPlayState: playState, '--birdo-globe-dot': dotColor } as React.CSSProperties}
        >
          {[0, 50].map((tileOffset) =>
            dots.map((d) => (
              <span
                key={`${tileOffset}-${d.key}`}
                className="birdo-globe__dot"
                style={{
                  left: `${tileOffset + d.left}%`,
                  top: `${d.top}%`,
                  transform: d.selected ? 'scale(1.5)' : undefined,
                }}
              />
            )),
          )}
        </div>
        <div className="birdo-globe__shade" />
        <div className="birdo-globe__rim" />
      </div>
      <div
        className="birdo-globe__atmo"
        style={{ '--birdo-globe-atmo': atmo } as React.CSSProperties}
      />
    </div>
  );
}

// `brand` re-export touch so the import is used even if the palette is later
// inlined; keeps the connected/idle tint colours discoverable in one place.
export const GLOBE_ACCENT = { idle: brand.purple, connected: '#44D17E' } as const;
