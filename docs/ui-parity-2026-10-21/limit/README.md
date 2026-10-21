# Limit tab: before and after (owner, 2026-10-21)

The owner asked for the whole Limit tab to look like the mobile app's, with the
speedometer gauge. The reference is the code on Mobile-Client `main` (7e627c4b):
Android `ui/screen/LimitScreen.kt` (`SpeedDialGauge`) and iOS
`iosApp/Views/LimitView.swift`. The store screenshots in that repo
(`fdroid/.../phoneScreenshots/01-05.png`, `store-assets/screenshot-0*.png`)
do not include the Limit tab, so there is no mobile image to put beside these.

## How they were taken

These screenshots come from the real `TitleBar`, `<Limit />` and `<BottomNav />`
over the app's `PixelCanvas`, rendered by the harness at
`src/__tests__/visual/limit-harness.html`. The harness fakes the Tauri bridge
and answers `get_usage_stats` with the reading named by `?s=`. It ran under
`vite` and was captured with headless Microsoft Edge (Chromium, the same
engine as WebView2) at 380 px wide:

```
msedge --headless=new --force-device-scale-factor=2 --window-size=380,640 \
  --virtual-time-budget=4000 --screenshot=out.png \
  "http://127.0.0.1:5199/src/__tests__/visual/limit-harness.html?s=half"
```

At 380 x 640 the window crops the tab, so the `*-full` images use a 380 x 1010
window to show all of it, including the upgrade card. The `before-*` images
are `origin/main` (eefd40b7, 1.4.49) in the same harness.

| Before (1.4.49) | After |
|---|---|
| `before-50pct-full.png`: linear bar, "View plans" | `after-50pct-full.png`: 270° dial, knob at the top, "Upgrade for unlimited" |
| `before-over-cap.png` | `after-over-cap-full.png`: red, full dial, "0.0 GB" left, "You're almost out of data" |
| `before-unlimited.png` | `after-unlimited.png`: mobile's unlimited state |
| `before-load-failed.png`: red banner and an icon | `after-load-failed.png`: mobile's message and Retry inside the card |

More states, after only:

- `after-0pct.png`: empty dial, knob at the start
- `after-1pct.png`: 0.52 GB
- `after-80pct-yellow.png`: yellow band from 75 %
- `after-never-synced.png`: "Awaiting first sync"
- `after-loading.png`: the loading state

Motion, 1x scale:

- `after-sweep-midway.png`: the fill partway through its 900 ms sweep, with
  the knob at its tip
- `after-reduced-motion-100pct.png`: with `prefers-reduced-motion`, the dial
  is drawn at its value straight away
