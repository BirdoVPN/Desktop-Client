/**
 * WorldGlobe — full-bleed orthographic globe rendered with the HTML5 Canvas 2D
 * API, a faithful port of mobile's Compose `WorldGlobe.kt` (no three.js).
 *
 * Visual goals (1:1 with the mobile spec / Color.kt globe palette):
 *  - Deep-space rect fill (#030714 dark / #EEF1F8 light), ~STAR_COUNT twinkling
 *    stars, a soft atmospheric halo feathered at the limb.
 *  - Ocean sphere radial gradient (core #1A3050 -> rim #071426) offset toward
 *    the light, three-tier sun-lit landmass (dim/mid/lit) drawn from real
 *    Natural Earth country polygons (world-atlas 110m TopoJSON) projected onto
 *    the sphere, clipped to the visible hemisphere with hairline borders.
 *  - A crawling day/night terminator, brand-purple server dots with halos, a
 *    great-circle connection arc (purple idle / green connected) that animates
 *    in when connected, and a default user pin at London (51.51, -0.13).
 *
 * The component is a presentational background only: it reads servers /
 * selected id / connected state and theme; it never calls invoke().
 *
 * Palette constants mirror mobile's `Color.kt` globe tokens exactly — keep them
 * in sync with:
 *   birdo-client-mobile/app/src/main/java/app/birdo/vpn/ui/theme/Color.kt
 */
import { useEffect, useMemo, useRef } from 'react';
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

// ── Globe palette (mirrors mobile Color.kt — dark / dim-light pairs) ─────────
interface GlobePalette {
  space: string;
  star: string;
  oceanCore: string;
  oceanRim: string;
  landDim: string;
  landMid: string;
  landLit: string;
  atmosphere: string;
  rim: string;
  accent: string;
  connected: string;
  nightAlpha: number;
  dayAlpha: number;
  limbAlpha: number;
  specAlpha: number;
  rimAlpha: number;
}

const DARK_PALETTE: GlobePalette = {
  space: '#030714',
  star: '#B6C5E2',
  oceanCore: '#1A3050',
  oceanRim: '#071426',
  landDim: '#1F4364',
  landMid: '#356D9F',
  landLit: '#59A8E0',
  atmosphere: '#4983C7',
  rim: '#7BB2E6',
  accent: brand.purple, // #A855F7
  connected: '#44D17E',
  nightAlpha: 0.55,
  dayAlpha: 0.18,
  limbAlpha: 0.3,
  specAlpha: 0.1,
  rimAlpha: 0.5,
};

const LIGHT_PALETTE: GlobePalette = {
  space: '#EEF1F8',
  star: '#8B95AB',
  oceanCore: '#D8E0EE',
  oceanRim: '#AEBACF',
  landDim: '#6E7C95',
  landMid: '#7E8DA6',
  landLit: '#98A6BE',
  atmosphere: '#8AAACE',
  rim: '#6E96C2',
  accent: '#B794F6', // dim-light softer violet
  connected: '#1F8F4E',
  nightAlpha: 0.22,
  dayAlpha: 0.1,
  limbAlpha: 0.1,
  specAlpha: 0.18,
  rimAlpha: 0.32,
};

const STAR_COUNT = 90;
const USER_LAT = 51.51; // London
const USER_LON = -0.13;

// ── Real-world landmass (Natural Earth 110m country polygons) ────────────────
// world-atlas ships `countries-110m.json`, a TopoJSON of 177 countries at
// ~110m resolution (~10.5k vertices total). We convert it once to GeoJSON,
// flatten every polygon ring into a pre-projected 3D unit-vector list, and
// store each country's centroid direction for sun-lit shading. The rings are
// projected + hemisphere-clipped per frame in `drawLand` (cheap at this size).

const D2R = Math.PI / 180;

/** A polygon ring as pre-computed unit-sphere vectors (one per source vertex). */
interface RingVec {
  x: Float64Array;
  y: Float64Array;
  z: Float64Array;
  n: number;
}

/** A country: its rings plus a centroid unit-vector for light-direction shading. */
interface LandCountry {
  rings: RingVec[];
  cx: number; // centroid unit vector (mean of ring vertices, re-normalised)
  cy: number;
  cz: number;
}

/** Convert one [lon,lat] ring → pre-projected unit vectors on the sphere. */
function ringToVec(coords: number[][]): RingVec | null {
  const n = coords.length;
  if (n < 3) return null;
  const x = new Float64Array(n);
  const y = new Float64Array(n);
  const z = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const lon = coords[i][0] * D2R;
    const lat = coords[i][1] * D2R;
    const cP = Math.cos(lat);
    x[i] = cP * Math.sin(lon);
    y[i] = Math.sin(lat);
    z[i] = cP * Math.cos(lon);
  }
  return { x, y, z, n };
}

/** Parse the TopoJSON → flattened country list (runs once at module load). */
function buildLand(): LandCountry[] {
  const fc = feature(worldData, worldData.objects.countries) as FeatureCollection<
    GeometryObject
  >;
  const out: LandCountry[] = [];
  for (const f of fc.features as Feature<GeometryObject>[]) {
    const geom = f.geometry;
    let polygons: number[][][][];
    if (geom.type === 'Polygon') {
      polygons = [geom.coordinates];
    } else if (geom.type === 'MultiPolygon') {
      polygons = geom.coordinates;
    } else {
      continue;
    }
    const rings: RingVec[] = [];
    let sx = 0;
    let sy = 0;
    let sz = 0;
    let count = 0;
    for (const poly of polygons) {
      for (const ring of poly) {
        const rv = ringToVec(ring);
        if (!rv) continue;
        rings.push(rv);
        for (let i = 0; i < rv.n; i++) {
          sx += rv.x[i];
          sy += rv.y[i];
          sz += rv.z[i];
        }
        count += rv.n;
      }
    }
    if (rings.length === 0 || count === 0) continue;
    const len = Math.hypot(sx, sy, sz) || 1;
    out.push({ rings, cx: sx / len, cy: sy / len, cz: sz / len });
  }
  return out;
}

// Parse once — the data is static, so this lives at module scope.
const LAND: LandCountry[] = buildLand();

interface StarDatum {
  x: number;
  y: number;
  b: number;
}
function precomputeStars(count: number): StarDatum[] {
  // Deterministic LCG so the field is stable across renders (mirrors mobile's
  // seeded Random).
  let seed = 0xb16d0;
  const rnd = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0xffffffff;
  };
  const out: StarDatum[] = [];
  for (let i = 0; i < count; i++) out.push({ x: rnd(), y: rnd(), b: rnd() });
  return out;
}

function lerpAngleDeg(a: number, b: number, t: number): number {
  let d = (b - a) % 360;
  if (d > 180) d -= 360;
  if (d < -180) d += 360;
  return a + d * t;
}

function withAlpha(hex: string, alpha: number): string {
  // Accepts #RRGGBB. Returns rgba() with the given alpha.
  const h = hex.replace('#', '');
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

type ServerPoint = { id: string; lat: number; lon: number };

export function WorldGlobe({
  servers,
  selectedServerId,
  isConnected = false,
  autoRotate = true,
  className = '',
}: WorldGlobeProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // One-shot precomputation. (Country polygons are parsed once at module load
  // into `LAND`; only the star field is per-component.)
  const stars = useMemo(() => precomputeStars(STAR_COUNT), []);

  const serverPoints = useMemo<ServerPoint[]>(() => {
    return servers
      .map((s) => {
        const ll = countryCoords(s.countryCode);
        return ll ? { id: s.id, lat: ll[0], lon: ll[1] } : null;
      })
      .filter((p): p is ServerPoint => p !== null);
  }, [servers]);

  const selectedCoord = useMemo<[number, number] | null>(() => {
    const sp = serverPoints.find((p) => p.id === selectedServerId);
    return sp ? [sp.lat, sp.lon] : null;
  }, [serverPoints, selectedServerId]);

  // Keep live props in a ref so the rAF loop always reads current values
  // without re-subscribing the animation frame.
  const stateRef = useRef({
    isConnected,
    autoRotate,
    serverPoints,
    selectedServerId,
    selectedCoord,
  });
  stateRef.current = { isConnected, autoRotate, serverPoints, selectedServerId, selectedCoord };

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    // Opaque context: the globe always paints a full opaque frame (space fill +
    // sphere). Declaring it non-alpha stops the compositor from alpha-blending
    // it against layers behind, which is what produced the translucent vertical
    // banding / ghosting on some GPUs. Also lets the browser skip a clear.
    const ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Animated tween targets (smoothly chased each frame, mirroring mobile's
    // animateFloatAsState springs).
    let focus = 0;
    let zoom = 1;
    let arcProgress = 0;

    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    let cssW = container.clientWidth;
    let cssH = container.clientHeight;

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      cssW = container.clientWidth;
      cssH = container.clientHeight;
      canvas.width = Math.max(1, Math.round(cssW * dpr));
      canvas.height = Math.max(1, Math.round(cssH * dpr));
      canvas.style.width = `${cssW}px`;
      canvas.style.height = `${cssH}px`;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    const isLightTheme = () => document.documentElement.classList.contains('light');

    let raf = 0;
    const start = performance.now();

    const draw = (now: number) => {
      const t = (now - start) / 1000;
      const { isConnected: connected, autoRotate: rotate, serverPoints: pts, selectedServerId: selId, selectedCoord: selCoord } =
        stateRef.current;

      // ── Loop phases (seconds → 0..1). Frozen when reduced-motion. ──────────
      const phase = (periodMs: number) => (reduceMotion ? 0 : ((t * 1000) % periodMs) / periodMs);
      const pulse = phase(1800);
      const arcShimmer = phase(2400);
      const twinkle = phase(3600);
      const idleSpin = reduceMotion ? 0 : ((t * 1000) % 90000) / 90000 * 360;
      const sunSpin = reduceMotion ? 0 : ((t * 1000) % 120000) / 120000 * 360;

      // ── Focal target (midpoint of user + server when something selected) ──
      const hasFocus = selCoord != null;
      let focusLatTarget = 0;
      let focusLonTarget = 0;
      if (hasFocus && selCoord) {
        const sLat = selCoord[0];
        let sLon = selCoord[1];
        const rawDLon = sLon - USER_LON;
        if (rawDLon > 180) sLon -= 360;
        else if (rawDLon < -180) sLon += 360;
        focusLatTarget = (USER_LAT + sLat) / 2;
        focusLonTarget = (USER_LON + sLon) / 2;
      }

      // Tween chase (exp smoothing approximates the Compose spring handoff).
      const k = reduceMotion ? 1 : 0.06;
      focus += ((hasFocus ? 1 : 0) - focus) * k;
      const zoomTarget = connected ? 1.2 : hasFocus ? 1.06 : 1;
      zoom += (zoomTarget - zoom) * k;
      const arcTarget = connected && hasFocus ? 1 : 0;
      arcProgress += (arcTarget - arcProgress) * (reduceMotion ? 1 : 0.05);

      const idleLon = rotate ? idleSpin + USER_LON - 25 : USER_LON;
      const effectiveLat = focusLatTarget * focus;
      const effectiveLon = lerpAngleDeg(idleLon, focusLonTarget, focus);

      const pal = isLightTheme() ? LIGHT_PALETTE : DARK_PALETTE;
      const sunLonDeg = 180 - sunSpin;
      const sunLatDeg = 12;

      renderGlobe(ctx, {
        w: cssW,
        h: cssH,
        dpr,
        pal,
        stars,
        isConnected: connected,
        focusLatDeg: effectiveLat,
        focusLonDeg: effectiveLon,
        zoom,
        twinkle,
        pulse,
        arcShimmer,
        arcProgress,
        serverPoints: pts,
        selectedServerId: selId ?? null,
        selectedCoord: selCoord,
        sunLatDeg,
        sunLonDeg,
      });

      if (!reduceMotion) raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    // Reduced motion: draw a couple of frames so tweens settle, then stop.
    if (reduceMotion) {
      const settle = () => {
        draw(performance.now());
      };
      const id = window.setInterval(settle, 60);
      window.setTimeout(() => window.clearInterval(id), 700);
      return () => {
        cancelAnimationFrame(raf);
        window.clearInterval(id);
        ro.disconnect();
      };
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [stars]);

  return (
    <div ref={containerRef} className={`absolute inset-0 ${className}`} aria-hidden>
      <canvas ref={canvasRef} className="block h-full w-full" />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering (single hot path, all state passed in)
// ─────────────────────────────────────────────────────────────────────────────
interface RenderArgs {
  w: number;
  h: number;
  dpr: number;
  pal: GlobePalette;
  stars: StarDatum[];
  isConnected: boolean;
  focusLatDeg: number;
  focusLonDeg: number;
  zoom: number;
  twinkle: number;
  pulse: number;
  arcShimmer: number;
  arcProgress: number;
  serverPoints: ServerPoint[];
  selectedServerId: string | null;
  selectedCoord: [number, number] | null;
  sunLatDeg: number;
  sunLonDeg: number;
}

function renderGlobe(ctx: CanvasRenderingContext2D, a: RenderArgs) {
  const { w, h, dpr, pal } = a;
  if (w <= 0 || h <= 0) return;

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  // Deep-space backdrop.
  ctx.fillStyle = pal.space;
  ctx.fillRect(0, 0, w, h);

  const cx = w * 0.5;
  const cy = h * 0.5;
  const baseR = Math.min(w, h) * 0.46;
  const radius = baseR * a.zoom;
  const atmR = radius * 1.22;
  const atmR2 = atmR * atmR;

  // ── Star field (occluded by the globe disc + atmosphere padding). ─────────
  const twoPi = Math.PI * 2;
  for (const s of a.stars) {
    const sx = s.x * w;
    const sy = s.y * h;
    const dx = sx - cx;
    const dy = sy - cy;
    if (dx * dx + dy * dy < atmR2) continue;
    const tw = 0.55 + 0.45 * Math.sin(a.twinkle * twoPi + s.b * 13.7);
    const alpha = (s.b * 0.65 + 0.18) * tw;
    ctx.beginPath();
    ctx.fillStyle = withAlpha(pal.star, alpha);
    ctx.arc(sx, sy, s.b > 0.85 ? 1.5 : 0.9, 0, twoPi);
    ctx.fill();
  }

  // ── Outer atmosphere — Fresnel-ish ring peaking just outside the limb. ────
  {
    const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, atmR);
    g.addColorStop(0.78, withAlpha(pal.atmosphere, 0));
    g.addColorStop(0.92, withAlpha(pal.atmosphere, pal.nightAlpha > 0.4 ? 0.36 : 0.22));
    g.addColorStop(1, withAlpha(pal.atmosphere, 0));
    ctx.beginPath();
    ctx.fillStyle = g;
    ctx.arc(cx, cy, atmR, 0, twoPi);
    ctx.fill();
  }

  // ── Ocean disc — directional radial gradient (lighter upper-left). ────────
  {
    const ocx = cx - radius * 0.22;
    const ocy = cy - radius * 0.28;
    const g = ctx.createRadialGradient(ocx, ocy, 0, ocx, ocy, radius * 1.05);
    g.addColorStop(0, pal.oceanCore);
    g.addColorStop(1, pal.oceanRim);
    ctx.beginPath();
    ctx.fillStyle = g;
    ctx.arc(cx, cy, radius, 0, twoPi);
    ctx.fill();
  }

  // Camera trig (focus the point at screen centre). `D2R` is module scope.
  const latRad = a.focusLatDeg * D2R;
  const lonRad = a.focusLonDeg * D2R;
  const cosLat = Math.cos(latRad);
  const sinLat = Math.sin(latRad);
  const cosLon = Math.cos(lonRad);
  const sinLon = Math.sin(lonRad);

  // Directional light (upper-left, towards camera).
  const lx = -0.42;
  const ly = -0.55;
  const lz = 0.72;

  // Project a (lat, lon) sample → screen Offset or null if back-facing.
  const project = (latDeg: number, lonDeg: number): [number, number] | null => {
    const phi = latDeg * D2R;
    const lam = lonDeg * D2R - lonRad;
    const cP = Math.cos(phi);
    const sP = Math.sin(phi);
    const sx = cP * Math.sin(lam);
    const sy = sP;
    const sz = cP * Math.cos(lam);
    const ty = sy * cosLat - sz * sinLat;
    const tz = sy * sinLat + sz * cosLat;
    if (tz < 0) return null;
    return [cx + sx * radius, cy - ty * radius];
  };

  // ── Continents: project real Natural Earth country polygons onto the sphere,
  // clip each ring to the visible hemisphere (bridging across the limb so a
  // coastline crossing the horizon hugs the disc edge instead of cutting a
  // chord), then fill shaded by the country centroid's angle to the light and
  // stroke a hairline border. ───────────────────────────────────────────────
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, twoPi); // hard clip to the disc (safety net)
  ctx.clip();
  ctx.lineJoin = 'round';
  const borderColor = withAlpha(pal.rim, pal.rimAlpha * 0.55);
  for (const country of LAND) {
    // Centroid lighting (camera-space) → pick one of three brightness buckets.
    const csx = country.cx * cosLon - country.cz * sinLon;
    const csz = country.cx * sinLon + country.cz * cosLon;
    const cty = country.cy * cosLat - csz * sinLat;
    const ctz = country.cy * sinLat + csz * cosLat;
    const litDot = csx * lx + cty * ly + ctz * lz;
    const fillColor = litDot > 0.45 ? pal.landLit : litDot > 0.05 ? pal.landMid : pal.landDim;

    ctx.beginPath();
    let drewRing = false;
    for (const ring of country.rings) {
      drewRing = traceRing(ctx, ring, cx, cy, radius, cosLat, sinLat, cosLon, sinLon) || drewRing;
    }
    if (!drewRing) continue; // country wholly on the far hemisphere
    ctx.fillStyle = fillColor;
    ctx.fill('evenodd');
    ctx.lineWidth = 0.6;
    ctx.strokeStyle = borderColor;
    ctx.stroke();
  }
  ctx.restore();

  // ── Inner limb darkening — vignette ring near the disc edge. ──────────────
  {
    const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius);
    g.addColorStop(0, 'rgba(0,0,0,0)');
    g.addColorStop(0.65, 'rgba(0,0,0,0)');
    g.addColorStop(1, `rgba(0,0,0,${pal.limbAlpha})`);
    ctx.beginPath();
    ctx.fillStyle = g;
    ctx.arc(cx, cy, radius, 0, twoPi);
    ctx.fill();
  }

  // ── Cool-blue rim stroke at the limb. ─────────────────────────────────────
  ctx.beginPath();
  ctx.strokeStyle = withAlpha(pal.rim, pal.rimAlpha);
  ctx.lineWidth = 1.2;
  ctx.arc(cx, cy, radius - 0.5, 0, twoPi);
  ctx.stroke();

  // ── Specular highlight (upper-left). ──────────────────────────────────────
  {
    const hx = cx - radius * 0.45;
    const hy = cy - radius * 0.55;
    const g = ctx.createRadialGradient(hx, hy, 0, hx, hy, radius * 0.55);
    g.addColorStop(0, `rgba(255,255,255,${pal.specAlpha})`);
    g.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, twoPi);
    ctx.clip();
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
    ctx.restore();
  }

  // ── Day / night terminator ────────────────────────────────────────────────
  {
    const sPhi = a.sunLatDeg * D2R;
    const sLam = a.sunLonDeg * D2R - lonRad;
    const sCp = Math.cos(sPhi);
    const ux = sCp * Math.sin(sLam);
    const uy = Math.sin(sPhi);
    const uz = sCp * Math.cos(sLam);
    const sxCam = ux;
    const syCam = uy * cosLat - uz * sinLat;
    const szCam = uy * sinLat + uz * cosLat;
    const sunPx = cx + sxCam * radius;
    const sunPy = cy - syCam * radius;
    const antiPx = cx - sxCam * radius;
    const antiPy = cy + syCam * radius;

    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, twoPi);
    ctx.clip();

    // Night veil — dark blob centred on the anti-solar point.
    {
      const g = ctx.createRadialGradient(antiPx, antiPy, 0, antiPx, antiPy, radius * 1.6);
      g.addColorStop(0, withAlpha('#02060F', pal.nightAlpha));
      g.addColorStop(0.55, withAlpha('#02060F', pal.nightAlpha * 0.55));
      g.addColorStop(1, 'rgba(2,6,15,0)');
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);
    }
    // Warm sunlit hotspot — only when the sun is on the visible hemisphere.
    if (szCam > 0) {
      const g = ctx.createRadialGradient(sunPx, sunPy, 0, sunPx, sunPy, radius * 0.7);
      g.addColorStop(0, withAlpha('#FFE6B0', pal.dayAlpha * szCam));
      g.addColorStop(1, 'rgba(255,230,176,0)');
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);
    }
    ctx.restore();
  }

  // ── Server dots — all visible by default; skip the selected one (it gets a
  // bigger pin in the connection block). ────────────────────────────────────
  for (const sp of a.serverPoints) {
    if (sp.id === a.selectedServerId) continue;
    const phi = sp.lat * D2R;
    const lam = sp.lon * D2R - lonRad;
    const cP = Math.cos(phi);
    const sxs = cP * Math.sin(lam);
    const sys = Math.sin(phi);
    const szs = cP * Math.cos(lam);
    const ty = sys * cosLat - szs * sinLat;
    const tz = sys * sinLat + szs * cosLat;
    if (tz <= 0.02) continue;
    const px = cx + sxs * radius;
    const py = cy - ty * radius;
    const depth = Math.max(0, Math.min(1, tz));
    const al = 0.55 + 0.45 * depth;
    const haloR = 6.5 + a.pulse * 1.8;
    drawDisc(ctx, px, py, haloR, withAlpha(pal.accent, 0.18 * al));
    drawDisc(ctx, px, py, haloR * 0.62, withAlpha(pal.accent, 0.3 * al));
    drawDisc(ctx, px, py, 3.2, withAlpha(pal.accent, 0.95 * al));
    drawDisc(ctx, px, py, 1.3, `rgba(255,255,255,${0.85 * al})`);
  }

  // ── Connection: great-circle arc (slerp + project), then pins. ────────────
  if (a.selectedCoord) {
    const arcColor = a.isConnected ? pal.connected : pal.accent;
    drawGreatCircleArc(ctx, {
      cx,
      cy,
      radius,
      cosLat,
      sinLat,
      cosLon,
      sinLon,
      startLat: USER_LAT,
      startLon: USER_LON,
      endLat: a.selectedCoord[0],
      endLon: a.selectedCoord[1],
      progress: a.arcProgress,
      shimmer: a.arcShimmer,
      color: arcColor,
    });
    const userPos = project(USER_LAT, USER_LON);
    const srvPos = project(a.selectedCoord[0], a.selectedCoord[1]);
    if (userPos) drawGlobePin(ctx, userPos[0], userPos[1], a.isConnected ? pal.connected : pal.accent, a.pulse, true);
    if (srvPos) drawGlobePin(ctx, srvPos[0], srvPos[1], pal.accent, a.pulse, false);
  } else {
    const userPos = project(USER_LAT, USER_LON);
    if (userPos) drawGlobePin(ctx, userPos[0], userPos[1], withAlpha(pal.accent, 0.95), a.pulse, true);
  }
}

/**
 * Trace one country ring onto the current path, clipped to the visible
 * hemisphere of the orthographic globe.
 *
 * Each vertex's pre-computed unit vector is rotated into camera space; a vertex
 * is visible when its camera-space z (`tz`) is ≥ 0. We emit the visible runs of
 * the ring and, wherever the coastline dips behind the limb and returns, bridge
 * the gap with an arc that follows the disc edge (`arcLimb`) — so partially
 * visible landmasses hug the sphere instead of being cut by a straight chord.
 * Returns true if any sub-path was added (ring touches the visible hemisphere).
 */
function traceRing(
  ctx: CanvasRenderingContext2D,
  ring: RingVec,
  cx: number,
  cy: number,
  radius: number,
  cosLat: number,
  sinLat: number,
  cosLon: number,
  sinLon: number,
): boolean {
  const n = ring.n;
  // Camera-space transform of a ring vertex by index.
  const camAt = (i: number): { sx: number; ty: number; tz: number } => {
    const x = ring.x[i];
    const y = ring.y[i];
    const z = ring.z[i];
    const sx = x * cosLon - z * sinLon;
    const sz = x * sinLon + z * cosLon;
    const ty = y * cosLat - sz * sinLat;
    const tz = y * sinLat + sz * cosLat;
    return { sx, ty, tz };
  };

  // Linear-interpolate the limb crossing between a visible and a hidden vertex,
  // then push it onto the rim circle. Returns the screen point + its rim angle.
  const limbCross = (
    aCam: { sx: number; ty: number; tz: number },
    bCam: { sx: number; ty: number; tz: number },
  ): { px: number; py: number; ang: number } => {
    const t = aCam.tz / (aCam.tz - bCam.tz); // tz = 0 between a (vis) and b (hid)
    let sx = aCam.sx + (bCam.sx - aCam.sx) * t;
    let ty = aCam.ty + (bCam.ty - aCam.ty) * t;
    const len = Math.hypot(sx, ty) || 1;
    sx /= len;
    ty /= len; // onto the unit rim
    return { px: cx + sx * radius, py: cy - ty * radius, ang: Math.atan2(-ty, sx) };
  };

  let started = false; // a sub-path is open on the ctx path
  let exitAng = 0; // rim angle where we last went behind the limb
  let haveExit = false; // an unmatched limb exit awaits a re-entry bridge
  let any = false;

  // Iterate every edge (i → i+1) with wrap-around; GeoJSON rings are closed so
  // vertex 0 == vertex n-1, making the wrap edge degenerate (harmless).
  let prev = camAt(0);
  for (let i = 1; i <= n; i++) {
    const cur = camAt(i % n);
    const aVis = prev.tz >= 0;
    const bVis = cur.tz >= 0;

    if (aVis && bVis) {
      // Wholly visible edge.
      if (!started) {
        ctx.moveTo(cx + prev.sx * radius, cy - prev.ty * radius);
        started = true;
      }
      ctx.lineTo(cx + cur.sx * radius, cy - cur.ty * radius);
      any = true;
    } else if (aVis && !bVis) {
      // Leaving the visible hemisphere — draw to the limb crossing, pen up.
      if (!started) {
        ctx.moveTo(cx + prev.sx * radius, cy - prev.ty * radius);
        started = true;
      }
      const c = limbCross(prev, cur);
      ctx.lineTo(c.px, c.py);
      exitAng = c.ang;
      haveExit = true;
      any = true;
    } else if (!aVis && bVis) {
      // Re-entering — find the entry crossing, bridge along the limb from the
      // last exit if we have one, then continue along the coastline.
      const c = limbCross(cur, prev); // order so the visible end is first
      if (started && haveExit) {
        arcLimb(ctx, cx, cy, radius, exitAng, c.ang);
        ctx.lineTo(cx + cur.sx * radius, cy - cur.ty * radius);
      } else {
        ctx.moveTo(c.px, c.py);
        ctx.lineTo(cx + cur.sx * radius, cy - cur.ty * radius);
        started = true;
      }
      haveExit = false;
      any = true;
    }
    // (!aVis && !bVis): edge fully hidden — nothing to draw.

    prev = cur;
  }
  if (started) ctx.closePath();
  return any;
}

/**
 * Append an arc along the globe limb between two rim angles, choosing the short
 * way round so the bridged coastline cannot loop the wrong side of the disc.
 */
function arcLimb(
  ctx: CanvasRenderingContext2D,
  cx: number,
  cy: number,
  radius: number,
  fromAng: number,
  toAng: number,
): void {
  // Screen angle for ctx.arc uses +y downward; our rim angle uses -ty, so the
  // ctx angle is the negative of our math angle.
  let from = -fromAng;
  let to = -toAng;
  let delta = to - from;
  while (delta > Math.PI) delta -= Math.PI * 2;
  while (delta < -Math.PI) delta += Math.PI * 2;
  to = from + delta;
  ctx.arc(cx, cy, radius, from, to, delta < 0);
}

function drawDisc(ctx: CanvasRenderingContext2D, x: number, y: number, r: number, color: string) {
  ctx.beginPath();
  ctx.fillStyle = color;
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fill();
}

/** Mullvad-style pin: outer translucent halo + filled disc + inner white dot. */
function drawGlobePin(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  color: string,
  pulse: number,
  small: boolean,
) {
  const halo = (small ? 11 : 17) + pulse * 5;
  const disc = small ? 5 : 7;
  const inner = small ? 2 : 2.8;
  const rgb = toRgb(color);
  drawDisc(ctx, x, y, halo, `rgba(${rgb},0.18)`);
  drawDisc(ctx, x, y, halo * 0.62, `rgba(${rgb},0.34)`);
  drawDisc(ctx, x, y, disc, color);
  drawDisc(ctx, x, y, inner, '#FFFFFF');
}

/** Parse #RRGGBB or rgba(...) into an "r,g,b" string for alpha compositing. */
function toRgb(color: string): string {
  if (color.startsWith('#')) {
    const h = color.replace('#', '');
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    return `${r},${g},${b}`;
  }
  const m = color.match(/rgba?\(([^)]+)\)/);
  if (m) {
    const parts = m[1].split(',').map((s) => s.trim());
    return `${parts[0]},${parts[1]},${parts[2]}`;
  }
  return '168,85,247';
}

interface ArcArgs {
  cx: number;
  cy: number;
  radius: number;
  cosLat: number;
  sinLat: number;
  cosLon: number;
  sinLon: number;
  startLat: number;
  startLon: number;
  endLat: number;
  endLon: number;
  progress: number;
  shimmer: number;
  color: string;
}

/**
 * Great-circle arc on the unit sphere via slerp, projected segment-by-segment.
 * Naturally clips to the visible hemisphere — the polyline simply breaks when a
 * segment dips behind the limb. Lift > 1 floats the arc just off the surface.
 */
function drawGreatCircleArc(ctx: CanvasRenderingContext2D, a: ArcArgs) {
  if (a.progress <= 0.001) return;
  const D2R = Math.PI / 180;
  const phi1 = a.startLat * D2R;
  const lam1 = a.startLon * D2R;
  const phi2 = a.endLat * D2R;
  const lam2 = a.endLon * D2R;
  const ax = Math.cos(phi1) * Math.sin(lam1);
  const ay = Math.sin(phi1);
  const az = Math.cos(phi1) * Math.cos(lam1);
  const bx = Math.cos(phi2) * Math.sin(lam2);
  const by = Math.sin(phi2);
  const bz = Math.cos(phi2) * Math.cos(lam2);
  let dot = ax * bx + ay * by + az * bz;
  dot = Math.max(-1, Math.min(1, dot));
  const omega = Math.acos(dot);
  if (omega < 1e-3) return;
  const sinO = Math.sin(omega);
  const segments = 64;
  const travel = Math.max(2, Math.floor(segments * a.progress));

  const camProject = (ux: number, uy: number, uz: number): { px: number; py: number; tz: number } => {
    const sx = ux * a.cosLon - uz * a.sinLon;
    const sz0 = ux * a.sinLon + uz * a.cosLon;
    const ty = uy * a.cosLat - sz0 * a.sinLat;
    const tz = uy * a.sinLat + sz0 * a.cosLat;
    return { px: a.cx + sx * a.radius, py: a.cy - ty * a.radius, tz };
  };

  ctx.beginPath();
  let pen = false;
  let anyDrawn = false;
  for (let seg = 0; seg <= travel; seg++) {
    const t = seg / segments;
    const sa = Math.sin((1 - t) * omega) / sinO;
    const sb = Math.sin(t * omega) / sinO;
    const lift = 1 + 0.045 * Math.sin(Math.PI * t);
    const ux = (sa * ax + sb * bx) * lift;
    const uy = (sa * ay + sb * by) * lift;
    const uz = (sa * az + sb * bz) * lift;
    const { px, py, tz } = camProject(ux, uy, uz);
    if (tz < 0) {
      pen = false;
    } else {
      if (!pen) {
        ctx.moveTo(px, py);
        pen = true;
      } else {
        ctx.lineTo(px, py);
      }
      anyDrawn = true;
    }
  }
  if (!anyDrawn) return;

  const rgb = toRgb(a.color);
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.strokeStyle = `rgba(${rgb},0.10)`;
  ctx.lineWidth = 12;
  ctx.stroke();
  ctx.strokeStyle = `rgba(${rgb},0.22)`;
  ctx.lineWidth = 6;
  ctx.stroke();
  ctx.strokeStyle = `rgba(${rgb},0.95)`;
  ctx.lineWidth = 2.4;
  ctx.stroke();

  // Travelling shimmer once the arc is fully drawn.
  if (a.progress >= 0.99) {
    const t = Math.max(0, Math.min(1, a.shimmer));
    const sa = Math.sin((1 - t) * omega) / sinO;
    const sb = Math.sin(t * omega) / sinO;
    const ux = (sa * ax + sb * bx) * 1.045;
    const uy = (sa * ay + sb * by) * 1.045;
    const uz = (sa * az + sb * bz) * 1.045;
    const { px, py, tz } = camProject(ux, uy, uz);
    if (tz >= 0) {
      drawDisc(ctx, px, py, 6, `rgba(${rgb},0.45)`);
      drawDisc(ctx, px, py, 2.6, 'rgba(255,255,255,0.9)');
    }
  }
}
