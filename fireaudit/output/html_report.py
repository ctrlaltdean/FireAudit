"""HTML report generator using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader

from fireaudit.data.framework_urls import get_control_url

# Inline template to keep the project self-contained
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FireAudit Report — {{ report.device.hostname or report.device.vendor }}</title>
<style>
  :root {
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #65a30d; --info: #0284c7; --pass: #16a34a; --fail: #dc2626;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1e293b; }
  header { background: #1e293b; color: white; padding: 2rem; }
  header h1 { font-size: 1.75rem; font-weight: 700; }
  header p { margin-top: .5rem; opacity: .7; font-size: .9rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
  .card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  .card .value { font-size: 2.5rem; font-weight: 700; }
  .card .label { font-size: .85rem; color: #64748b; margin-top: .25rem; }
  .pass .value { color: var(--pass); }
  .fail .value { color: var(--fail); }
  .score-card { border-top: 4px solid #6366f1; }
  .posture-banner { background: white; border-radius: 8px; padding: 1.5rem 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1.5rem; display: flex; align-items: center; gap: 2rem; }
  .posture-grade { font-size: 4rem; font-weight: 800; line-height: 1; min-width: 80px; text-align: center; }
  .posture-grade.A { color: #16a34a; } .posture-grade.B { color: #65a30d; }
  .posture-grade.C { color: #d97706; } .posture-grade.D { color: #ea580c; } .posture-grade.F { color: #dc2626; }
  .posture-detail { flex: 1; }
  .posture-detail h2 { font-size: 1rem; font-weight: 600; margin-bottom: .5rem; }
  .posture-bar-wrap { height: 12px; background: #e2e8f0; border-radius: 6px; overflow: hidden; margin: .5rem 0; }
  .posture-bar { height: 100%; border-radius: 6px; }
  .posture-bar.A, .posture-bar.B { background: #16a34a; }
  .posture-bar.C { background: #d97706; } .posture-bar.D { background: #ea580c; } .posture-bar.F { background: #dc2626; }
  .posture-score-num { font-size: 2rem; font-weight: 700; }
  section { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1.5rem; }
  section h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; padding-bottom: .5rem; border-bottom: 1px solid #e2e8f0; }
  .fw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
  .fw-card { border: 1px solid #e2e8f0; border-radius: 6px; padding: 1rem; }
  .fw-card h3 { font-size: .9rem; font-weight: 600; margin-bottom: .5rem; }
  .progress { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; margin: .5rem 0; }
  .progress-bar { height: 100%; border-radius: 4px; transition: width .3s; }
  .progress-bar.green { background: var(--pass); }
  .progress-bar.amber { background: var(--medium); }
  .progress-bar.red { background: var(--fail); }
  .score-text { font-size: .8rem; color: #64748b; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { background: #f1f5f9; padding: .6rem 1rem; text-align: left; font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: #64748b; }
  td { padding: .75rem 1rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 9999px; font-size: .75rem; font-weight: 600; }
  .badge.critical { background: #fef2f2; color: var(--critical); }
  .badge.high { background: #fff7ed; color: var(--high); }
  .badge.medium { background: #fffbeb; color: var(--medium); }
  .badge.low { background: #f7fee7; color: var(--low); }
  .badge.info { background: #f0f9ff; color: var(--info); }
  .badge.pass { background: #f0fdf4; color: var(--pass); }
  .badge.fail { background: #fef2f2; color: var(--fail); }
  .badge.error { background: #f5f3ff; color: #7c3aed; }
  .badge.manual_check { background: #fefce8; color: #854d0e; }
  .manual-note { font-size: .8rem; background: #fefce8; border-left: 3px solid #ca8a04; padding: .5rem .75rem; margin-top: .5rem; color: #713f12; }
  .remediation { font-size: .8rem; background: #f8fafc; border-left: 3px solid #6366f1; padding: .5rem .75rem; margin-top: .5rem; color: #475569; }
  .vendor-cmd { font-size: .8rem; background: #f0fdf4; border-left: 3px solid #16a34a; padding: .5rem .75rem; margin-top: .5rem; color: #166534; }
  .vendor-cmd pre { margin-top: .25rem; font-family: monospace; white-space: pre-wrap; font-size: .75rem; }
  .affected { font-family: monospace; font-size: .75rem; color: #64748b; margin-top: .25rem; }
  details > summary { cursor: pointer; font-size: .8rem; color: #6366f1; margin-top: .25rem; }
  details[open] { margin-top: .5rem; }
  .filter-bar { display: flex; gap: .75rem; margin-bottom: 1rem; flex-wrap: wrap; }
  .filter-bar select, .filter-bar input { padding: .4rem .75rem; border: 1px solid #e2e8f0; border-radius: 6px; font-size: .85rem; }
  .device-meta td:first-child { font-weight: 500; width: 200px; }
  footer { text-align: center; padding: 2rem; font-size: .8rem; color: #94a3b8; }
  @media print {
    header { background: #1e293b !important; -webkit-print-color-adjust: exact; }
    .filter-bar { display: none; }
  }
</style>
</head>
<body>

<header>
  <h1>FireAudit Security Report</h1>
  <p>Generated {{ report.generated_at }} &nbsp;|&nbsp;
     {{ report.device.vendor | upper }} {{ report.device.hostname or "" }}
     {% if report.device.firmware_version %}&nbsp;|&nbsp; FW: {{ report.device.firmware_version }}{% endif %}
  </p>
</header>

<div class="container">

  <!-- Posture score banner -->
  {% if report.posture_score %}
  {% set ps = report.posture_score %}
  {% set grade = ps.grade %}
  <div class="posture-banner">
    <div class="posture-grade {{ grade }}">{{ grade }}</div>
    <div class="posture-detail">
      <h2>Security Posture Score</h2>
      <div class="posture-bar-wrap">
        <div class="posture-bar {{ grade }}" style="width: {{ ps.score }}%"></div>
      </div>
      <span class="posture-score-num">{{ ps.score }}<span style="font-size:1rem;font-weight:400;color:#64748b;">/100</span></span>
      &nbsp;&nbsp;
      <span style="font-size:.85rem;color:#64748b;">
        {{ ps.fail_count }} fail &nbsp;·&nbsp; {{ ps.pass_count }} pass
        {% if ps.not_applicable_count %}&nbsp;·&nbsp; {{ ps.not_applicable_count }} N/A{% endif %}
        {% if ps.manual_check_count %}&nbsp;·&nbsp; {{ ps.manual_check_count }} manual{% endif %}
      </span>
    </div>
    <div style="text-align:right;min-width:160px;font-size:.8rem;color:#64748b;">
      {% for sev in ["critical","high","medium","low"] %}
      {% set cnt = ps.fail_counts.get(sev, 0) %}
      {% if cnt %}
      <div><span style="color:var(--{{sev}});font-weight:600;">{{ cnt }} {{ sev }}</span></div>
      {% endif %}
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- Summary cards -->
  <div class="grid">
    <div class="card">
      <div class="value">{{ report.summary.total_rules }}</div>
      <div class="label">Rules Evaluated</div>
    </div>
    {% if report.summary.manual_check %}
    <div class="card" style="border-top:4px solid #ca8a04;">
      <div class="value" style="color:#ca8a04;">{{ report.summary.manual_check }}</div>
      <div class="label">Manual Checks Required</div>
    </div>
    {% endif %}
    <div class="card pass">
      <div class="value">{{ report.summary.pass }}</div>
      <div class="label">Passed</div>
    </div>
    <div class="card fail">
      <div class="value">{{ report.summary.fail }}</div>
      <div class="label">Failed</div>
    </div>
    {% for sev in ["critical", "high", "medium", "low"] %}
    {% set sev_data = report.summary.by_severity.get(sev, {}) %}
    {% if sev_data %}
    <div class="card">
      <div class="value" style="color: var(--{{ sev }})">{{ sev_data.get("fail", 0) }}</div>
      <div class="label">{{ sev | capitalize }} Failures</div>
    </div>
    {% endif %}
    {% endfor %}
  </div>

  <!-- Compliance scores -->
  {% if report.compliance_scores %}
  <section>
    <h2>Framework Compliance Scores</h2>
    <div class="fw-grid">
      {% for fw, data in report.compliance_scores.items() %}
      {% set score = data.score_percent %}
      <div class="fw-card">
        <h3>{{ fw }}</h3>
        <div class="progress">
          <div class="progress-bar {% if score >= 80 %}green{% elif score >= 60 %}amber{% else %}red{% endif %}"
               style="width: {{ score }}%"></div>
        </div>
        <div class="score-text">{{ score }}% — {{ data.pass }} pass / {{ data.fail }} fail</div>
      </div>
      {% endfor %}
    </div>
  </section>
  {% endif %}

  <!-- Device info -->
  <section>
    <h2>Device Information</h2>
    <table class="device-meta">
      <tr><td>Vendor</td><td>{{ report.device.vendor }}</td></tr>
      <tr><td>Hostname</td><td>{{ report.device.hostname or "—" }}</td></tr>
      <tr><td>Model</td><td>{{ report.device.model or "—" }}</td></tr>
      <tr><td>Firmware</td><td>{{ report.device.firmware_version or "—" }}</td></tr>
      <tr><td>Source File</td><td>{{ report.device.source_file or "—" }}</td></tr>
    </table>
  </section>

  <!-- Findings table -->
  <section>
    <h2>Findings</h2>
    <div class="filter-bar">
      <select id="sev-filter" onchange="filterTable()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select id="status-filter" onchange="filterTable()">
        <option value="">All Statuses</option>
        <option value="fail">Fail</option>
        <option value="pass">Pass</option>
        <option value="error">Error</option>
        <option value="manual_check">Manual Check</option>
      </select>
      <input id="search" type="text" placeholder="Search…" oninput="filterTable()">
    </div>
    <table id="findings-table">
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Name</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Details / Remediation</th>
        </tr>
      </thead>
      <tbody>
        {% for f in report.findings %}
        <tr data-sev="{{ f.severity }}" data-status="{{ f.status }}">
          <td><code>{{ f.rule_id }}</code></td>
          <td>
            {{ f.name }}
            {% if f.frameworks %}
            <details>
              <summary>Framework mappings</summary>
              {% for fw, controls in f.frameworks.items() %}
              <div style="margin:.25rem 0;font-size:.75rem;">
                <strong>{{ fw }}:</strong>
                {% if controls is string %}
                  {% set url = fw_url(fw, controls) %}
                  {% if url %}<a href="{{ url }}" target="_blank" rel="noopener" style="color:#6366f1;">{{ controls }}</a>{% else %}{{ controls }}{% endif %}
                {% else %}
                  {% for ctrl in controls %}
                    {% set url = fw_url(fw, ctrl) %}
                    {% if url %}<a href="{{ url }}" target="_blank" rel="noopener" style="color:#6366f1;">{{ ctrl }}</a>{% else %}{{ ctrl }}{% endif %}{% if not loop.last %},<br>{% endif %}
                  {% endfor %}
                {% endif %}
              </div>
              {% endfor %}
            </details>
            {% endif %}
          </td>
          <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
          <td><span class="badge {{ f.status }}">{{ f.status }}</span></td>
          <td>
            {% if f.details %}<div class="affected">{{ f.details }}</div>{% endif %}
            {% if f.affected_paths %}
            <div class="affected">Path: {{ f.affected_paths | join(", ") }}</div>
            {% endif %}
            {% if f.status == "fail" and f.remediation %}
            <div class="remediation">{{ f.remediation }}</div>
            {% endif %}
            {% if f.status == "fail" and f.vendor_command %}
            <div class="vendor-cmd">
              <strong>CLI Fix ({{ report.device.vendor | upper }}):</strong>
              <pre>{{ f.vendor_command }}</pre>
            </div>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>

  {% set manual_findings = report.findings | selectattr('status', 'eq', 'manual_check') | list %}
  {% if manual_findings %}
  <section style="border-top: 4px solid #ca8a04;">
    <h2>&#9888; Manual Verification Required</h2>
    <p style="font-size:.875rem;color:#64748b;margin-bottom:1rem;">
      The following checks cannot be determined from static configuration analysis alone.
      Each item must be verified manually by a qualified engineer before the audit can be
      considered complete.
    </p>
    <table>
      <thead>
        <tr>
          <th>Check ID</th>
          <th>Check</th>
          <th>Result</th>
          <th>Guidance</th>
        </tr>
      </thead>
      <tbody>
        {% for f in manual_findings %}
        <tr>
          <td><code>{{ f.rule_id }}</code></td>
          <td>
            {{ f.name }}
            {% if f.frameworks %}
            <details>
              <summary>Framework mappings</summary>
              {% for fw, controls in f.frameworks.items() %}
              <div style="margin:.25rem 0;font-size:.75rem;">
                <strong>{{ fw }}:</strong>
                {% if controls is string %}
                  {% set url = fw_url(fw, controls) %}
                  {% if url %}<a href="{{ url }}" target="_blank" rel="noopener" style="color:#6366f1;">{{ controls }}</a>{% else %}{{ controls }}{% endif %}
                {% else %}
                  {% for ctrl in controls %}
                    {% set url = fw_url(fw, ctrl) %}
                    {% if url %}<a href="{{ url }}" target="_blank" rel="noopener" style="color:#6366f1;">{{ ctrl }}</a>{% else %}{{ ctrl }}{% endif %}{% if not loop.last %},<br>{% endif %}
                  {% endfor %}
                {% endif %}
              </div>
              {% endfor %}
            </details>
            {% endif %}
          </td>
          <td style="white-space:nowrap;">
            {% if f.manual_result == "confirmed_ok" %}
              <span class="badge pass">✓ Confirmed OK</span>
            {% elif f.manual_result == "needs_attention" %}
              <span class="badge fail">✗ Needs Attention</span>
            {% else %}
              <span class="badge manual_check">Not Reviewed</span>
            {% endif %}
          </td>
          <td>
            {% if f.details %}<div class="manual-note">{{ f.details }}</div>{% endif %}
            {% if f.remediation %}<div class="remediation">{{ f.remediation }}</div>{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

</div>

<footer>Generated by <strong>FireAudit</strong> — Offline firewall configuration auditing</footer>

<script>
function filterTable() {
  const sev = document.getElementById('sev-filter').value;
  const status = document.getElementById('status-filter').value;
  const search = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {
    const matchSev = !sev || row.dataset.sev === sev;
    const matchStatus = !status || row.dataset.status === status;
    const matchSearch = !search || row.textContent.toLowerCase().includes(search);
    row.style.display = (matchSev && matchStatus && matchSearch) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


def render_html(report: dict, output_path: str | Path | None = None) -> str:
    """Render an HTML report from a report dict. Returns HTML string."""
    # Pre-sort findings: fail/error first by severity, then pass, N/A, manual
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    _sta = {"fail": 0, "error": 1, "pass": 2, "not_applicable": 3, "manual_check": 4}
    sorted_report = {**report, "findings": sorted(
        report.get("findings", []),
        key=lambda f: (_sta.get(f.get("status", "pass"), 5), _sev.get(f.get("severity", "info"), 5)),
    )}

    env = Environment(loader=BaseLoader())
    env.globals["fw_url"] = get_control_url
    template = env.from_string(_TEMPLATE)
    html = template.render(report=sorted_report)

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
