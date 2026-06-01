// Ambient declaration for the bundled Natural Earth TopoJSON shipped by
// `world-atlas`. The package ships raw JSON with no types; Vite imports JSON
// natively, and this declaration gives tsc the precise `Topology` shape so the
// data can be handed straight to topojson-client's `feature()`.
declare module 'world-atlas/countries-110m.json' {
  import type { Topology } from 'topojson-specification';
  const topology: Topology;
  export default topology;
}
