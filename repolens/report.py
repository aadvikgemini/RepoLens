"""Report generation module for RepoLens (Person C).

Produces report.json and a standalone report.html dashboard.
"""
from __future__ import annotations

import dataclasses
import json
import os
from typing import Any, Dict
from .models import Report

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RepoLens Integrity Report - {{ report.package_name }}@{{ report.version }}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#3b82f6', 600: '#2563eb' }
          }
        }
      }
    }
  </script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    pre code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-8">
  <div class="max-w-6xl mx-auto space-y-6">
    <!-- Header -->
    <header class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center font-black text-blue-400 text-xl">
          🔍
        </div>
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            RepoLens <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Hackathon Report</span>
          </h1>
          <p class="text-xs text-slate-400">Published Package vs Source Code Integrity Analyzer</p>
        </div>
      </div>
      <div class="text-right text-xs text-slate-400">
        <div>Analyzed: <strong class="text-slate-200">{{ report.package_name }}@{{ report.version }}</strong></div>
        <div>Ref: <code class="text-blue-400">{{ report.commit_or_tag or 'Not Found / Synthetic' }}</code></div>
      </div>
    </header>

    <!-- Verdict Banner -->
    <section class="rounded-2xl p-6 border {% if report.overall_verdict == 'CLEAN' %}bg-emerald-950/30 border-emerald-500/30 text-emerald-300{% elif report.overall_verdict == 'WARNING' %}bg-amber-950/30 border-amber-500/30 text-amber-300{% else %}bg-rose-950/30 border-rose-500/30 text-rose-300{% endif %}">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div class="text-xs uppercase tracking-wider font-semibold opacity-75">Overall Integrity Verdict</div>
          <div class="text-4xl font-extrabold tracking-tight mt-1">{{ report.overall_verdict }}</div>
          <p class="text-sm mt-2 text-slate-300">
            {% if report.overall_verdict == 'CLEAN' %}
              No suspicious tampering detected between the published npm package and the git source code.
            {% elif report.overall_verdict == 'WARNING' %}
              Unexplained differences detected (e.g. modified files or build artifacts without verified source map), but no verified high-risk payload.
            {% else %}
              CRITICAL: Suspicious discrepancies or high-risk signals detected in the published npm package!
            {% endif %}
          </p>
        </div>
        <div class="flex flex-col items-center sm:items-end justify-center bg-slate-900/60 p-4 rounded-xl border border-slate-800 min-w-[150px]">
          <span class="text-xs text-slate-400">Risk Score</span>
          <span class="text-4xl font-black mt-0.5 {% if report.overall_verdict == 'CLEAN' %}text-emerald-400{% elif report.overall_verdict == 'WARNING' %}text-amber-400{% else %}text-rose-400{% endif %}">
            {{ report.overall_risk_score }}<span class="text-lg text-slate-500 font-normal">/100</span>
          </span>
        </div>
      </div>
    </section>

    <!-- File Stats -->
    <section class="grid grid-cols-2 sm:grid-cols-4 gap-4">
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400 font-medium">Identical Files</div>
        <div class="text-2xl font-bold text-slate-100 mt-1">{{ report.metadata.file_counts.identical }}</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400 font-medium">Modified Files</div>
        <div class="text-2xl font-bold text-amber-400 mt-1">{{ report.metadata.file_counts.modified }}</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400 font-medium">Only in Package</div>
        <div class="text-2xl font-bold text-rose-400 mt-1">{{ report.metadata.file_counts.only_in_package }}</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400 font-medium">Only in Source</div>
        <div class="text-2xl font-bold text-blue-400 mt-1">{{ report.metadata.file_counts.only_in_source }}</div>
      </div>
    </section>

    <!-- Findings Section -->
    <section class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
      <div class="p-5 border-b border-slate-800 flex items-center justify-between">
        <h2 class="text-lg font-semibold text-white">Discrepancy Findings ({{ report.findings|length }})</h2>
        <span class="text-xs text-slate-400">Classified by static heuristics & LLM reasoning</span>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-slate-300">
          <thead class="bg-slate-950/60 text-xs uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th class="py-3 px-4">Risk</th>
              <th class="py-3 px-4">Classification</th>
              <th class="py-3 px-4">File Path</th>
              <th class="py-3 px-4">Detected Signals</th>
              <th class="py-3 px-4">Explanation & Evidence</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            {% if not report.findings %}
              <tr>
                <td colspan="5" class="py-8 text-center text-slate-500">No discrepancies detected! The published package matches source perfectly.</td>
              </tr>
            {% endif %}
            {% for f in report.findings %}
              <tr class="hover:bg-slate-800/40 transition-colors">
                <td class="py-3 px-4 align-top">
                  <span class="px-2 py-0.5 rounded text-xs font-bold {% if f.risk_level == 'HIGH' %}bg-rose-500/20 text-rose-400 border border-rose-500/30{% elif f.risk_level == 'MEDIUM' %}bg-amber-500/20 text-amber-400 border border-amber-500/30{% else %}bg-slate-800 text-slate-400{% endif %}">
                    {{ f.risk_level }}
                  </span>
                </td>
                <td class="py-3 px-4 align-top font-mono text-xs">
                  <span class="{% if f.classification == 'SUSPICIOUS' %}text-rose-400 font-semibold{% elif f.classification == 'UNEXPLAINED' %}text-amber-400{% else %}text-emerald-400{% endif %}">
                    {{ f.classification }}
                  </span>
                </td>
                <td class="py-3 px-4 align-top font-mono text-xs text-white max-w-[200px] truncate" title="{{ f.file_path }}">
                  {{ f.file_path }}
                </td>
                <td class="py-3 px-4 align-top">
                  <div class="flex flex-wrap gap-1">
                    {% for sig in f.signals %}
                      <span class="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-mono">
                        {{ sig }}
                      </span>
                    {% else %}
                      <span class="text-slate-500 text-xs">none</span>
                    {% endfor %}
                  </div>
                </td>
                <td class="py-3 px-4 align-top text-xs space-y-2 max-w-[400px]">
                  <p class="text-slate-300 leading-relaxed">{{ f.explanation }}</p>
                  {% if f.evidence %}
                    <details class="text-[11px] bg-slate-950 border border-slate-800 rounded p-2">
                      <summary class="cursor-pointer text-slate-400 hover:text-slate-200 font-mono">View Snippet Evidence</summary>
                      <pre class="mt-2 text-rose-300 overflow-x-auto whitespace-pre-wrap font-mono">{{ f.evidence[:800] }}</pre>
                    </details>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Notes & Diagnostics -->
    {% if report.metadata.notes %}
    <section class="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs text-slate-400">
      <div class="font-semibold text-slate-300 mb-2">Analysis Notes:</div>
      <ul class="list-disc list-inside space-y-1">
        {% for note in report.metadata.notes %}
          <li>{{ note }}</li>
        {% endfor %}
      </ul>
    </section>
    {% endif %}

    <!-- Footer -->
    <footer class="text-center text-xs text-slate-600 pt-4">
      RepoLens Integrity Analyzer &bull; Built by Team Sparrow (Hacktoberfest Hack Day Sonipat)
    </footer>
  </div>
</body>
</html>
"""


def generate_html_report(report: Report) -> str:
    """Render a standalone HTML report from a Report dataclass instance."""
    try:
        from jinja2 import Template
        tmpl = Template(HTML_TEMPLATE)
        return tmpl.render(report=report)
    except Exception:
        # Fallback basic HTML if jinja fails for any reason
        return f"""<!DOCTYPE html>
<html><head><title>RepoLens Report - {report.package_name}</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;">
<h1>RepoLens Report: {report.package_name}@{report.version}</h1>
<h2>Verdict: {report.overall_verdict} (Risk: {report.overall_risk_score}/100)</h2>
<p>Commit/Tag: {report.commit_or_tag}</p>
<h3>Findings ({len(report.findings)}):</h3>
<ul>{"".join(f"<li><b>[{f.risk_level}] {f.classification}</b> {f.file_path}: {f.explanation}</li>" for f in report.findings)}</ul>
</body></html>"""


def write_reports(report: Report, out_dir: str) -> None:
    """Write report.json and report.html to the given directory."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    html_path = os.path.join(out_dir, "report.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(report), f, indent=2)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(report))
