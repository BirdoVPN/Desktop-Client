# UI parity screenshots, 2026-10-21

Before/after evidence for the PR "fix(ui): data cap in GB (not raw bytes), one
server name per row like mobile, no background animation on Connect".

| File | Shows |
|---|---|
| `connect.png` | Mobile Connect (main) · Desktop before (pixel grid behind the globe) · Desktop after (no grid, as on mobile) |
| `server-sheet.png` | Mobile sheet · Desktop before (pinned "Fastest server" row, every name twice) · Desktop after (one name per row) |
| `profile.png` | Desktop before ("53687091200 GB / month") · Desktop after ("50 GB / month") |
| `other-tabs-keep-grid.png` | Mobile Settings · Desktop Limit and Settings after: the grid stays on every tab but Connect, as on mobile |

Mobile images are `fdroid/metadata/app.birdo.vpn/en-US/phoneScreenshots/02-04.png`
from Mobile-Client main 7e627c4b. Desktop images are the real `App` built with
Vite from `src/` (before: Desktop-Client main eefd40b7; after: this branch), with
the Tauri APIs stubbed to canned data (an anonymous free account with a 50 GiB
cap, ten nodes named `birdo-vpn-<city>`) and rendered by headless Chromium at
400×780. Windows Chromium has no flag emoji, so flags render as letters ("DE"),
as they do in the WebView2 app.
