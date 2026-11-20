# Screenshots

The images in `docs/screenshots/` were captured from a local install. They show live CISA KEV data
plus the clearly labelled **synthetic** demo dataset.

| File | Page |
|---|---|
| `overview.png` / `overview-light.png` | Overview (dark and light themes) |
| `threat-feed.png` | Threat Feed cards with source citations |
| `cve-explorer.png` | CVE Explorer table |
| `ioc-explorer.png` | IOC Explorer (defanged, synthetic indicators) |
| `actors.png` | Threat Actors & Campaigns (synthetic profile) |
| `trends.png` | KEV additions by week and ransomware use |
| `settings.png` | Sources, credential status, sync history |

## Capturing your own

1. Prepare the data:

   ```bash
   siren ingest --source cisa_kev
   ```

   Optionally add the demo data:

   ```bash
   siren seed-demo
   ```

2. Start the dashboard:

   ```bash
   siren dashboard
   ```

   Then open <http://127.0.0.1:8501>.
3. Use your OS screenshot tool (Windows: <kbd>Win</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd>; macOS:
   <kbd>⌘</kbd>+<kbd>Shift</kbd>+<kbd>4</kbd>; Linux: <kbd>PrtSc</kbd>). Switch themes from the
   ⋮ menu → Settings.
4. **Before sharing**, make sure screenshots contain no internal notes, watchlist entries, tags or
   other organisation-specific data.

To automate capture, use Playwright (`pip install playwright && playwright install chromium`), then
`page.goto("http://127.0.0.1:8501/cves")` and `page.screenshot(path=...)`. Pass
`color_scheme="dark"` or `"light"` to `browser.new_context()` to choose the theme.
