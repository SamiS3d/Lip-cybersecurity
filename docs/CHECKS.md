# Checks Reference

This document describes CoreInspect checks at a high level.

> Notes:
> - Checks are designed to be **safe** and primarily configuration-focused.
> - Some checks are **heuristics** and may produce false positives/negatives.
> - Always verify findings manually before taking action.

## TLS / HTTPS
### HTTP → HTTPS Redirect
- **What it checks**: whether the HTTP endpoint redirects to HTTPS.
- **Why it matters**: protects traffic against interception.
- **Fix**: redirect all HTTP to HTTPS; consider HSTS.

### HSTS (Strict-Transport-Security)
- **What it checks**: whether HSTS is set on HTTPS hosts.
- **Fix**: add `Strict-Transport-Security` with appropriate `max-age`.

## Headers
CoreInspect flags missing security headers such as:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options` / `frame-ancestors` via CSP
- `Referrer-Policy`
- `Permissions-Policy`

## Cookies
Flags missing cookie attributes (when `Set-Cookie` is present):
- `Secure` (especially on HTTPS)
- `HttpOnly`
- `SameSite`

## CORS
Heuristic checks for risky patterns like:
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`

## Exposure (Sensitive Paths)
Probes a small list of common sensitive paths (best-effort), for example:
- `/.env`
- `/.git/HEAD`
- `/phpinfo.php`

## Forms
Heuristics:
- POST forms without an obvious CSRF token name (contains `csrf` or `token`)
- Password forms with non-HTTPS action

## Active (Non-destructive) Reflection Checks
- Sends a **benign marker** value to test if input is reflected.
- This can indicate a potential injection surface that needs review.
- It does **not** attempt exploitation.