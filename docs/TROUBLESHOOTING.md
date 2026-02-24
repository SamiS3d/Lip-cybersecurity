# Troubleshooting

## Playwright timeouts during crawling
Some sites continuously load resources, causing `networkidle` timeouts.
CoreInspect uses `domcontentloaded` to reduce this risk.

If you still see timeouts:
- Increase timeout: `--timeout 20` (or higher)
- Reduce max pages: `--max-pages 20`
- Try passive profile first

## `ModuleNotFoundError` for packages
Make sure each package folder includes `__init__.py`:
- `core/__init__.py`
- `checks/__init__.py`
- `reporting/__init__.py`
- `scoring/__init__.py`
- `utils/__init__.py`

Run from the project root (where `main.py` exists).

## `xdg-open` wildcard issue
Open the latest HTML report with:
```bash
xdg-open "$(ls -t reports/*.html | head -n 1)"
```

## Playwright browser missing
Install Chromium:
```bash
playwright install chromium
```