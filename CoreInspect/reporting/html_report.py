from html import escape
from datetime import datetime


def _sev_class(sev: str) -> str:
    sev = (sev or "").lower()
    if sev == "critical":
        return "sev-critical"
    if sev == "high":
        return "sev-high"
    if sev == "medium":
        return "sev-medium"
    if sev == "low":
        return "sev-low"
    return "sev-info"


def render_html_report(target: str, profile: str, score_result, findings: list, generated_at: str | None = None) -> str:
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    score = score_result.score if score_result else None
    grade = score_result.grade if score_result else None
    deductions = score_result.deductions if score_result else None
    breakdown = score_result.breakdown if score_result else {}
    top_issues = score_result.top_issues if score_result else []

    findings_rows = []
    for idx, f in enumerate(findings, 1):
        findings_rows.append(f"""
          <tr>
            <td class="idx">{idx}</td>
            <td class="sev {_sev_class(f.severity)}">{escape(f.severity)}</td>
            <td class="cat">{escape(f.category)}</td>
            <td class="title">{escape(f.title)}</td>
            <td class="url"><a href="{escape(f.url)}" target="_blank" rel="noreferrer">{escape(f.url)}</a></td>
          </tr>
          <tr class="details">
            <td colspan="5">
              <div><b>Evidence:</b> {escape(f.evidence or "-")}</div>
              <div><b>Recommendation:</b> {escape(f.recommendation or "-")}</div>
            </td>
          </tr>
        """)

    breakdown_items = "\n".join(
        f"<li><b>{escape(str(k))}</b>: {escape(str(v))}</li>" for k, v in breakdown.items()
    ) or "<li>-</li>"

    top_items = "\n".join(
        f"<li><span class='pill {_sev_class(i.get('severity'))}'>{escape(i.get('severity','Info'))}</span> "
        f"{escape(i.get('title',''))} <span class='muted'>({escape(i.get('url',''))})</span></li>"
        for i in top_issues
    ) or "<li>-</li>"

    score_box = ""
    if score is not None:
        score_box = f"""
        <div class="scorebox">
          <div class="score">{score}<span>/100</span></div>
          <div class="grade">Grade: <b>{escape(str(grade))}</b></div>
          <div class="deductions">Deductions: {escape(str(deductions))}</div>
        </div>
        """

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CoreInspect Report - {escape(target)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --card: #101a2f;
      --text: #e7eefc;
      --muted: #a9b7d0;
      --line: rgba(255,255,255,.08);
      --good: #26d07c;
      --warn: #f6c445;
      --bad:  #ff4d4d;
      --info: #7aa7ff;
    }}
    body {{
      margin: 0; padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }}
    a {{ color: #9ec3ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      display:flex; gap:16px; align-items:flex-start; justify-content:space-between;
      padding: 18px; border:1px solid var(--line); background: var(--card); border-radius: 14px;
    }}
    .meta .h1 {{ font-size: 18px; font-weight: 700; margin: 0 0 6px 0; }}
    .meta .row {{ color: var(--muted); font-size: 13px; line-height: 1.5; }}
    .scorebox {{
      text-align:right;
      min-width: 220px;
    }}
    .score {{
      font-size: 44px; font-weight: 800; line-height: 1;
    }}
    .score span {{ font-size: 14px; color: var(--muted); font-weight: 600; }}
    .grade, .deductions {{ color: var(--muted); font-size: 13px; margin-top: 6px; }}
    .grid {{
      display:grid; grid-template-columns: 1fr 1fr; gap: 16px;
      margin-top: 16px;
    }}
    .card {{
      padding: 16px; border:1px solid var(--line); background: var(--card); border-radius: 14px;
    }}
    h2 {{ margin: 0 0 10px 0; font-size: 15px; }}
    ul {{ margin: 0; padding-left: 18px; color: var(--muted); }}
    .pill {{
      display:inline-block; padding: 2px 8px; border-radius: 999px;
      font-size: 12px; font-weight: 700; margin-right: 8px;
      border: 1px solid var(--line);
    }}
    .sev-critical {{ background: rgba(255,77,77,.15); color: var(--bad); }}
    .sev-high {{ background: rgba(255,77,77,.12); color: #ff8a8a; }}
    .sev-medium {{ background: rgba(246,196,69,.12); color: var(--warn); }}
    .sev-low {{ background: rgba(38,208,124,.10); color: var(--good); }}
    .sev-info {{ background: rgba(122,167,255,.10); color: var(--info); }}
    table {{
      width:100%; border-collapse: collapse; margin-top: 16px;
      border: 1px solid var(--line); border-radius: 14px; overflow:hidden;
      background: var(--card);
    }}
    thead th {{
      text-align:left; font-size: 12px; color: var(--muted);
      padding: 12px; border-bottom: 1px solid var(--line);
      background: rgba(255,255,255,.02);
    }}
    tbody td {{
      padding: 10px 12px; border-bottom: 1px solid var(--line);
      font-size: 13px; vertical-align: top;
    }}
    td.idx {{ width: 44px; color: var(--muted); }}
    td.sev {{ width: 95px; font-weight: 800; }}
    td.cat {{ width: 110px; color: var(--muted); }}
    td.url {{ color: var(--muted); word-break: break-all; }}
    tr.details td {{
      padding-top: 0;
      color: var(--muted);
      font-size: 12px;
    }}
    .muted {{ color: var(--muted); }}
    .footer {{ margin-top: 18px; color: var(--muted); font-size: 12px; }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .scorebox {{ text-align:left; }}
      .header {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="meta">
        <div class="h1">CoreInspect Security Audit Report</div>
        <div class="row"><b>Target:</b> {escape(target)}</div>
        <div class="row"><b>Profile:</b> {escape(profile)}</div>
        <div class="row"><b>Generated:</b> {escape(generated_at)}</div>
      </div>
      {score_box}
    </div>

    <div class="grid">
      <div class="card">
        <h2>Breakdown (Deduction caps per category)</h2>
        <ul>
          {breakdown_items}
        </ul>
      </div>

      <div class="card">
        <h2>Top issues</h2>
        <ul>
          {top_items}
        </ul>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>URL</th>
        </tr>
      </thead>
      <tbody>
        {''.join(findings_rows) if findings_rows else '<tr><td colspan="5" class="muted">No findings.</td></tr>'}
      </tbody>
    </table>

    <div class="footer">
      Generated by CoreInspect (security auditor). Use only on targets you own or have explicit permission to test.
    </div>
  </div>
</body>
</html>
"""
    return html
