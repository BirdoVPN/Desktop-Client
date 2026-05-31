/**
 * WorldGlobe — full-bleed orthographic globe rendered with the HTML5 Canvas 2D
 * API, a faithful port of mobile's Compose `WorldGlobe.kt` (no three.js).
 *
 * Visual goals (1:1 with the mobile spec / Color.kt globe palette):
 *  - Deep-space rect fill (#030714 dark / #EEF1F8 light), ~STAR_COUNT twinkling
 *    stars, a soft atmospheric halo feathered at the limb.
 *  - Ocean sphere radial gradient (core #1A3050 -> rim #071426) offset toward
 *    the light, three-tier sun-lit landmass (dim/mid/lit) drawn as a coarse
 *    lat/long cell grid masked to the continents.
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

// ── Coarse continent landmask ────────────────────────────────────────────────
// A faithful 720×360 bitmask is too heavy to port verbatim; per the brief a
// coarse dotted-grid sphere that reads as the mobile globe is acceptable. We
// approximate continents with a set of lat/lon boxes and sample them on a grid
// — the *look* is dotted violet-blue land on a dark sphere.
type Box = [latMin: number, latMax: number, lonMin: number, lonMax: number];
const CONTINENTS: Box[] = [
  // North America
  [49, 71, -168, -56], // Canada / Alaska
  [25, 49, -125, -67], // contiguous US
  [14, 30, -118, -86], // Mexico
  [7, 18, -92, -77], // Central America
  // Greenland
  [60, 83, -55, -18],
  // South America
  [-4, 12, -82, -60], // northern SA
  [-23, -4, -74, -35], // Brazil / central
  [-56, -23, -76, -53], // southern cone
  // Europe
  [43, 60, -10, 30], // core Europe
  [50, 71, 4, 60], // Scandinavia / Baltics / W. Russia
  [36, 44, -10, 28], // Iberia / Italy / Balkans
  [49, 60, -8, 2], // UK / Ireland
  // Africa
  [12, 37, -17, 35], // North Africa / Sahara
  [-5, 14, -17, 48], // sub-Saharan / Horn
  [-35, -5, 12, 41], // southern Africa
  // Middle East / Central Asia
  [12, 42, 34, 60],
  [35, 55, 50, 90],
  // Russia / Siberia
  [50, 73, 60, 180],
  // South Asia
  [6, 35, 68, 90],
  // East / SE Asia
  [20, 53, 100, 135], // China / Korea
  [30, 46, 129, 146], // Japan
  [-10, 28, 95, 141], // SE Asia / Indonesia
  // Australia
  [-39, -11, 113, 154],
  // New Zealand
  [-47, -34, 166, 179],
];

function isLand(latDeg: number, lonDeg: number): boolean {
  for (let i = 0; i < CONTINENTS.length; i++) {
    const b = CONTINENTS[i];
    if (latDeg >= b[0] && latDeg <= b[1] && lonDeg >= b[2] && lonDeg <= b[3]) {
      return true;
    }
  }
  return false;
}

interface LandSample {
  sinPhi: number;
  cosPhi: number;
  lonRad: number;
}

/** Pre-compute land cell centres on a lat/lon grid (runs once). */
function precomputeLandSamples(): { samples: LandSample[]; cellSizeRad: number } {
  const rows = 90; // 2° lat steps
  const cols = 180; // 2° lon steps
  const cellLat = Math.PI / rows;
  const samples: LandSample[] = [];
  for (let r = 0; r < rows; r++) {
    const latDeg = 90 - ((r + 0.5) * 180) / rows;
    const phi = (latDeg * Math.PI) / 180;
    const sinPhi = Math.sin(phi);
    const cosPhi = Math.cos(phi);
    for (let c = 0; c < cols; c++) {
      const lonDeg = -180 + ((c + 0.5) * 360) / cols;
      if (!isLand(latDeg, lonDeg)) continue;
      samples.push({ sinPhi, cosPhi, lonRad: (lonDeg * Math.PI) / 180 });
    }
  }
  return { samples, cellSizeRad: cellLat * 1.55 };
}

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

  // One-shot precomputation.
  const landSamples = useMemo(() => precomputeLandSamples(), []);
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
    const ctx = canvas.getContext('2d');
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
        landSamples,
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
  }, [landSamples, stars]);

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
  landSamples: { samples: LandSample[]; cellSizeRad: number };
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

  // Camera trig (focus the point at screen centre).
  const D2R = Math.PI / 180;
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

  // ── Continents: project precomputed samples, classify by lighting, draw
  // three brightness buckets as square cells. ───────────────────────────────
  const cellPx = radius * a.landSamples.cellSizeRad;
  const buckets: Array<{ color: string; cells: Array<[number, number, number]> }> = [
    { color: pal.landDim, cells: [] },
    { color: pal.landMid, cells: [] },
    { color: pal.landLit, cells: [] },
  ];
  for (const cell of a.landSamples.samples) {
    const lam = cell.lonRad - lonRad;
    const sinL = Math.sin(lam);
    const cosL = Math.cos(lam);
    const sx = cell.cosPhi * sinL;
    const sy = cell.sinPhi;
    const sz = cell.cosPhi * cosL;
    const ty = sy * cosLat - sz * sinLat;
    const tz = sy * sinLat + sz * cosLat;
    if (tz <= 0.02) continue;
    const px = cx + sx * radius;
    const py = cy - ty * radius;
    const dot = sx * lx + ty * ly + tz * lz;
    const half = cellPx * (0.55 + 0.45 * tz) * 0.5;
    const bi = dot > 0.55 ? 2 : dot > 0.2 ? 1 : 0;
    buckets[bi].cells.push([px, py, half]);
  }
  for (const bkt of buckets) {
    ctx.fillStyle = bkt.color;
    ctx.beginPath();
    for (const [px, py, half] of bkt.cells) {
      ctx.rect(px - half, py - half, half * 2, half * 2);
    }
    ctx.fill();
  }

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
