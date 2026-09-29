# Birdo VPN — Microsoft Store Listing (DRAFT — NOT PUBLISHED)

> **Status: not published.** The desktop app is not on the Microsoft Store and
> listing it is not a current goal (owner, OPEN-WORK F18). Nothing in this file
> is live anywhere. It is kept only as a draft, and was corrected on
> 2026-09-29 (audit A-25 / D-1 / D-4 / D-7) to match
> `AUDIT-2026-09-29/REMEDIATION-DECISIONS.md`: the previous draft claimed
> "RAM-only volatile infrastructure", "guaranteed leak protection", Rosenpass,
> split tunnelling, an in-app subscription and USD prices, none of which is
> true. If it is ever published, re-check every line against that file first.

## App Details

**App Name:** Birdo VPN
**Short Description (80 chars max):**
WireGuard® VPN with no activity logs, stealth mode and post-quantum key exchange.

**Category:** Security
**Content Rating:** Everyone (content rating; separately, the Terms of Service require users to be 18 or over)
**Contact Email:** support@birdo.app
**Website:** https://birdo.app
**Privacy Policy URL:** https://birdo.app/privacy
**Terms of Service URL:** https://birdo.app/terms
**Publisher:** Birdo Networks Ltd (company no. 17136571)

---

## Full Description (10,000 chars max)

Birdo VPN encrypts your internet connection with WireGuard® and sends it through
our VPN servers, so the sites you visit see the server's address instead of yours.

**No Activity Logs**
Our VPN servers don't record the sites you visit, your DNS queries or your
traffic. While you're connected, our account system keeps a live record of your
session (server, device, connect time). It is deleted when you disconnect and is
left out of our nightly backups. Our daily encrypted copy of the database files
(kept 7 days, used for point-in-time recovery) can contain it as it stood at that
moment. We also count your data use per billing period.

**What Your Account Holds**
Your email (or anonymous account number), plan, the devices you add, and your
usage totals. Full list: birdo.app/privacy.

**WireGuard® Protocol**
Built on the modern WireGuard protocol for fast connections with minimal CPU
overhead.

**Server Network**
Servers in several regions, each showing its current load.

**Kill Switch**
If the tunnel drops unexpectedly, the app blocks traffic until it reconnects.
Protection applies while the app is running. On Windows the block uses the
Windows Filtering Platform and, by default, stays on for the whole session.

**Kill Switch Exceptions (Windows)**
Let chosen apps keep working while the kill switch is blocking traffic. This is
not split tunnelling: while the VPN is connected, those apps' traffic still goes
through the VPN.

**Stealth Mode (paid plans)**
Wraps the VPN connection in Xray REALITY so it looks like ordinary HTTPS traffic,
for networks that block VPN protocols.

**Multi-Hop (Sovereign plan)**
Your traffic enters one server and leaves from another, so sites see the exit
server's address. It is not onion routing: the entry server can see your IP
address and the destinations you connect to.

**Post-Quantum Key Exchange**
Each connection adds a WireGuard pre-shared key derived with ML-KEM-1024
(BirdoPQ) between your app and our API. The key is then delivered to the VPN
server over TLS that is not yet post-quantum, so protection against "record now,
decrypt later" is only as strong as that link today.

**Two-Factor Authentication**
TOTP-based 2FA to protect your account. Works with any authenticator app.

**System Tray Integration**
Runs in the system tray. Connect, disconnect and switch servers without opening
the main window.

**Auto-Connect**
Optionally connect automatically when the app starts.

**Port Forwarding (Sovereign plan)**
Expose a local service through the VPN tunnel.

**Why Birdo VPN?**
• No advertising or analytics SDKs. Optional crash reporting (off unless you turn it on)
• No activity logs on our VPN servers (see above for the live session record)
• Source-available apps (CC BY-NC 4.0)
• Post-quantum key exchange (BirdoPQ, ML-KEM-1024) — see the caveat above
• Stealth mode for networks that block VPN protocols
• Multi-hop routing through two servers
• Kill switch while the app is running (Windows Filtering Platform)
• Two-factor authentication (2FA / TOTP)
• Port forwarding
• In-app data export and account deletion
• Built with Rust
• Not yet independently audited

**Technical Details:**
• Protocol: WireGuard®
• Encryption: ChaCha20-Poly1305
• Key Exchange: Curve25519, plus an ML-KEM-1024-derived pre-shared key (BirdoPQ)
• Kill Switch: Windows Filtering Platform (WFP)
• Framework: Tauri 2 (Rust + WebView2)
• Minimum Windows: 10 (64-bit)
• Installer: NSIS

---

## What's New

(Write from the release notes of the version actually submitted.)

---

## Screenshots Required

Create the following screenshots at 1366x768 or 1920x1080 (16:9):

1. **Main dashboard** — Connected state showing server, IP, connection time
2. **Server selection** — Server list with regions and load indicators
3. **Settings panel** — Kill switch, crash-report and auto-connect options
4. **Stealth mode** — Stealth mode toggle and connection
5. **Multi-hop** — Multi-hop route configuration
6. **Login screen** — Clean login with 2FA option
7. **Speed test** — Built-in speed test results
8. **System tray** — Tray icon with context menu

**Resolution:** At least 1366x768. Microsoft recommends 1920x1080.
**Format:** PNG
**Minimum:** 4 screenshots required

---

## Store Assets Required

- **App icon:** 300x300 PNG (source: icons/icon.ico)
- **Hero image:** 1920x1080 PNG (promotional banner)
- **Feature graphic:** Used in store listing header

---

## Pricing

**Free** to download, with a free plan (Recon: 1 device, 10 GB per month).
There is **no in-app purchase**: paid plans are bought on the web at
birdo.app, where Polar is the reseller (merchant of record), and the app only
links there.

- Operative: £3.99/month or £38/year (save 20% yearly)
- Sovereign: £9.99/month or £99/year (save 17% yearly)

Prices include VAT for customers in the UK, EU and most other countries. In the
United States, Canada and India, sales tax is added at checkout. Polar, our
reseller, shows the final total before you pay.

---

## Age Rating Questionnaire Answers

- Does the app contain violence? No
- Does the app contain sexual content? No
- Does the app facilitate gambling? No
- Does the app collect personal information? Yes (email or anonymous account
  number, devices, usage totals, optional crash reports — per the privacy policy)
- Does the app access the internet? Yes (VPN service)
- Does the app contain user-generated content? No
