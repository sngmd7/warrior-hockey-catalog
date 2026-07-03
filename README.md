# Warrior Hockey Catalog Share

Static GitHub Pages wrapper for the Secondslide Warrior Hockey customer catalog.

The published page stores the source HTML as an AES-GCM encrypted payload. Visitors need the shared password to decrypt and view it in the browser.

## Build

```bash
node scripts/build-protected-page.mjs /Users/sngmd/Downloads/secondslide-warrior-hockey-catalog-2026-07-03.html '<password>'
```

