from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

from .utils import RISK_ORDER

RISK_COLOR = {
    "CRITICAL": "#d1352b", "HIGH": "#e0792a", "MEDIUM": "#c7a311", "LOW": "#4a5565",
}


def write_reports(output_dir, system_info: dict, sections: dict, all_findings: list[dict]):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    sorted_findings = sorted(all_findings, key=lambda x: -RISK_ORDER.get(x["risk"], 0))

    json_path = output_dir / "privesc_enum.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"system": system_info, "sections": sections, "findings": sorted_findings},
                   f, indent=2, default=str)

    md_path = output_dir / "privesc_enum.md"
    _write_markdown(md_path, system_info, sorted_findings)

    html_path = output_dir / "privesc_enum.html"
    _write_html(html_path, system_info, sorted_findings)

    return json_path, md_path, html_path


def _write_markdown(path: Path, system_info: dict, findings: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Privilege Escalation Enumeration Report\n")
        f.write(f"_Generated {datetime.now(timezone.utc).isoformat()}Z_\n\n")
        f.write("> Diagnostic only. Nothing here was exploited. Verify manually and "
                "only act within an engagement you're authorized for.\n\n")

        f.write("## System\n")
        for k, v in system_info.items():
            f.write(f"- **{k}**: {v}\n")
        f.write("\n")

        f.write(f"## Findings ({len(findings)} total)\n\n")
        if not findings:
            f.write("_No flagged conditions found with this tool's checks. "
                    "That doesn't mean the box is clean — it means these specific "
                    "checks didn't trip. Keep looking manually._\n\n")
        for finding in findings:
            f.write(f"### [{finding['risk']}] {finding['category']}\n")
            f.write(f"{finding['detail']}\n")
            if finding.get("reference"):
                f.write(f"\nLook up the technique: {finding['reference']}\n")
            f.write("\n")


def _write_html(path: Path, system_info: dict, findings: list[dict]):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1

    rows = "".join(f"""
      <tr>
        <td><span class="badge" style="background:{RISK_COLOR[f['risk']]}22;color:{RISK_COLOR[f['risk']]}">{f['risk']}</span></td>
        <td>{f['category']}</td>
        <td>{f['detail']}</td>
        <td>{f'<a href="{f["reference"]}" target="_blank">lookup &rarr;</a>' if f.get('reference') else ''}</td>
      </tr>""" for f in findings)

    sys_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in system_info.items())
    empty_row = "<tr><td colspan=\"4\">No flagged conditions with this tool's checks.</td></tr>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Privesc Enumeration Report</title>
<style>
  :root {{ --bg:#0f1216; --panel:#171b21; --border:#262b33; --text:#e6e9ee; --muted:#8a93a1; }}
  body {{ background:var(--bg); color:var(--text); font-family:-apple-system,Segoe UI,sans-serif; margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin-bottom:4px; }}
  .subtitle {{ color:var(--muted); margin-bottom:24px; font-size:13px; }}
  .banner {{ background:#1a2230; border:1px solid #2d4a6e; border-radius:8px; padding:12px 16px; font-size:13px; margin-bottom:24px; color:#9cc0e8; }}
  .summary {{ display:flex; gap:12px; margin-bottom:24px; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 16px; min-width:90px; }}
  .card .count {{ font-size:22px; font-weight:700; }}
  .card .label {{ font-size:11px; color:var(--muted); text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:28px; }}
  th,td {{ padding:8px 10px; text-align:left; font-size:13px; border-bottom:1px solid var(--border); vertical-align:top; }}
  th {{ background:#1d222a; color:var(--muted); font-size:11px; text-transform:uppercase; }}
  .badge {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; }}
  h2 {{ font-size:14px; color:var(--muted); text-transform:uppercase; margin:20px 0 8px; }}
  a {{ color:#4a9eff; }}
</style></head>
<body>
  <h1>Privilege Escalation Enumeration Report</h1>
  <div class="subtitle">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
  <div class="banner">Diagnostic only. Nothing here was exploited or modified. Every finding points you to GTFOBins/HackTricks/the CVE database by name — verify manually and only act within an engagement you're authorized for.</div>

  <div class="summary">
    <div class="card"><div class="count" style="color:{RISK_COLOR['CRITICAL']}">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="card"><div class="count" style="color:{RISK_COLOR['HIGH']}">{counts['HIGH']}</div><div class="label">High</div></div>
    <div class="card"><div class="count" style="color:{RISK_COLOR['MEDIUM']}">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="card"><div class="count" style="color:{RISK_COLOR['LOW']}">{counts['LOW']}</div><div class="label">Low</div></div>
  </div>

  <h2>System</h2>
  <table><tbody>{sys_rows}</tbody></table>

  <h2>Findings ({len(findings)})</h2>
  <table>
    <thead><tr><th>Risk</th><th>Category</th><th>Detail</th><th></th></tr></thead>
    <tbody>{rows if rows else empty_row}</tbody>
  </table>
</body></html>"""
    path.write_text(html)
