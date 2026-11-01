"""RepoLens Web Server & Interactive Dashboard.

Provides a localhost web interface to analyze npm packages and inspect integrity reports.
"""
from __future__ import annotations

import dataclasses
import http.server
import json
import os
import shutil
import socketserver
import sys
import tarfile
import tempfile
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Dict

# Ensure repolens package is on sys.path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from repolens.models import Report
from repolens.pipeline import run_pipeline
from repolens.report import generate_html_report, write_reports
from scripts.make_tampered import make_tampered_fixture

DEFAULT_PORT = 8000
_LATEST_REPORT: Report | None = None
_LATEST_DIFFS: list[dict[str, Any]] = []

HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RepoLens — Integrity Analyzer Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace'],
          },
          colors: {
            surface: { 900: '#0a0d14', 850: '#0f1420', 800: '#161c2e', 700: '#232c45' },
            cyber: { cyan: '#00f2fe', blue: '#4facfe', green: '#10b981', rose: '#f43f5e', amber: '#f59e0b' }
          }
        }
      }
    }
  </script>
  <style>
    @keyframes pulse-glow {
      0%, 100% { opacity: 0.4; }
      50% { opacity: 0.9; }
    }
    .glow-cyan { filter: drop-shadow(0 0 16px rgba(0, 242, 254, 0.35)); }
    .glow-rose { filter: drop-shadow(0 0 16px rgba(244, 63, 94, 0.35)); }
    .glow-amber { filter: drop-shadow(0 0 16px rgba(245, 158, 11, 0.35)); }
    .glow-green { filter: drop-shadow(0 0 16px rgba(16, 185, 129, 0.35)); }
  </style>
</head>
<body class="bg-surface-900 text-slate-200 font-sans min-h-screen flex flex-col selection:bg-cyan-500/20 selection:text-cyan-300 antialiased">
  <!-- Top Navigation -->
  <header class="border-b border-surface-700/60 bg-surface-850/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center font-black text-slate-950 text-xl shadow-lg shadow-cyan-500/20">
          ⚡
        </div>
        <div>
          <div class="flex items-center gap-2">
            <span class="text-lg font-bold tracking-tight text-white">RepoLens</span>
            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 tracking-wider">v0.1.0</span>
            <span class="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Team Sparrow</span>
          </div>
          <p class="text-[11px] text-slate-400 hidden sm:block">Package vs Source Integrity Analyzer &bull; Hacktoberfest Hack Day Sonipat</p>
        </div>
      </div>

      <div class="flex items-center gap-3 text-xs">
        <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-surface-800 border border-surface-700 text-slate-300">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>Localhost:8000</span>
        </div>
        <a href="/report.html" target="_blank" id="viewHtmlBtn" class="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 font-medium transition">
          📄 View HTML Report
        </a>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-8">
    <!-- Hero / Controls Card -->
    <div class="rounded-2xl bg-surface-850 border border-surface-700/70 p-6 shadow-xl relative overflow-hidden">
      <div class="absolute -top-24 -right-24 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
      
      <div class="max-w-3xl space-y-2 mb-6">
        <h2 class="text-2xl font-bold text-white tracking-tight">Verify Published Package Integrity</h2>
        <p class="text-sm text-slate-400">
          Compare published npm tarballs against their canonical Git repositories. RepoLens decompresses, diffs, classifies discrepancies, scans for malicious lifecycle hooks & high-entropy obfuscation, and issues a final security verdict.
        </p>
      </div>

      <!-- Quick Preset Buttons -->
      <div class="mb-5 flex flex-wrap items-center gap-2">
        <span class="text-xs font-semibold text-slate-400 mr-1">Quick Demos:</span>
        <button onclick="runSyntheticDemo()" class="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-medium flex items-center gap-1.5 transition">
          🚨 <strong>Tampered Fixture</strong> (Attack Demo)
        </button>
        <button onclick="setPackage('is-odd', '3.0.1')" class="px-3 py-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-300 border border-surface-700 text-xs font-medium transition">
          📦 is-odd@3.0.1
        </button>
        <button onclick="setPackage('ms', '2.1.3')" class="px-3 py-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-300 border border-surface-700 text-xs font-medium transition">
          📦 ms@2.1.3
        </button>
        <button onclick="setPackage('chalk', '5.3.0')" class="px-3 py-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-300 border border-surface-700 text-xs font-medium transition">
          📦 chalk@5.3.0
        </button>
      </div>

      <!-- Input Form -->
      <form id="analyzeForm" class="flex flex-col sm:flex-row gap-3">
        <div class="flex-1 relative">
          <input 
            type="text" 
            id="pkgName" 
            placeholder="npm package name (e.g. is-odd, lodash, express)" 
            class="w-full h-12 px-4 rounded-xl bg-surface-900 border border-surface-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
            required
          />
        </div>
        <div class="w-full sm:w-44">
          <input 
            type="text" 
            id="pkgVersion" 
            placeholder="version (e.g. 3.0.1)" 
            class="w-full h-12 px-4 rounded-xl bg-surface-900 border border-surface-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
          />
        </div>
        <button 
          type="submit" 
          id="submitBtn" 
          class="h-12 px-6 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm tracking-wide flex items-center justify-center gap-2 transition shadow-lg shadow-cyan-500/25 disabled:opacity-50"
        >
          <span id="btnSpinner" class="hidden w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></span>
          <span id="btnText">Analyze Integrity</span>
        </button>
      </form>

      <!-- Status banner -->
      <div id="statusAlert" class="hidden mt-4 p-3 rounded-xl text-xs font-mono border"></div>
    </div>

    <!-- Results Section (Dynamic) -->
    <div id="resultsSection" class="space-y-6 hidden">
      <!-- Verdict & Risk Summary -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Verdict Banner -->
        <div id="verdictCard" class="lg:col-span-2 rounded-2xl p-6 border flex flex-col justify-between transition-all">
          <div>
            <div class="flex items-center justify-between">
              <span class="text-xs uppercase font-bold tracking-wider text-slate-400">Integrity Assessment Verdict</span>
              <span id="verdictBadge" class="text-xs font-extrabold uppercase px-3 py-1 rounded-full border"></span>
            </div>
            <div id="verdictTitle" class="text-4xl font-black tracking-tight mt-2 text-white"></div>
            <p id="verdictDesc" class="text-sm mt-3 text-slate-300 leading-relaxed"></p>
          </div>

          <div class="mt-6 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div>
              <span class="text-slate-500">Target:</span>
              <span id="resPackageTarget" class="font-mono text-cyan-400 font-semibold ml-1"></span>
            </div>
            <div>
              <span class="text-slate-500">Source Tag/Commit:</span>
              <span id="resSourceRef" class="font-mono text-slate-300 ml-1"></span>
            </div>
          </div>
        </div>

        <!-- Risk Score Gauge Card -->
        <div class="rounded-2xl bg-surface-850 border border-surface-700/70 p-6 flex flex-col items-center justify-center text-center">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Calculated Risk Index</span>
          <div class="relative flex items-center justify-center my-4">
            <svg class="w-36 h-36 transform -rotate-90" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" stroke="currentColor" stroke-width="10" class="text-surface-700" fill="transparent" />
              <circle id="scoreRing" cx="60" cy="60" r="50" stroke="currentColor" stroke-width="10" stroke-linecap="round" fill="transparent"
                stroke-dasharray="314.159" stroke-dashoffset="314.159" class="transition-all duration-1000 ease-out" />
            </svg>
            <div class="absolute flex flex-col items-center">
              <span id="scoreText" class="text-4xl font-black text-white">0</span>
              <span class="text-[11px] font-semibold text-slate-500 uppercase">out of 100</span>
            </div>
          </div>
          <p id="scoreLabel" class="text-xs font-semibold px-3 py-1 rounded-lg border"></p>
        </div>
      </div>

      <!-- File Metrics Grid -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div class="rounded-xl bg-surface-850 border border-surface-700/70 p-4">
          <div class="text-xs text-slate-400 font-medium">Identical Files</div>
          <div id="cntIdentical" class="text-3xl font-black text-slate-100 mt-1">0</div>
          <div class="text-[10px] text-slate-500 mt-1">Byte-for-byte SHA256 match</div>
        </div>
        <div class="rounded-xl bg-surface-850 border border-surface-700/70 p-4">
          <div class="text-xs text-slate-400 font-medium">Modified Files</div>
          <div id="cntModified" class="text-3xl font-black text-amber-400 mt-1">0</div>
          <div class="text-[10px] text-slate-500 mt-1">Differ from source repo</div>
        </div>
        <div class="rounded-xl bg-surface-850 border border-surface-700/70 p-4">
          <div class="text-xs text-slate-400 font-medium">Only in Package</div>
          <div id="cntPkgOnly" class="text-3xl font-black text-rose-400 mt-1">0</div>
          <div class="text-[10px] text-slate-500 mt-1">Artifacts or injected files</div>
        </div>
        <div class="rounded-xl bg-surface-850 border border-surface-700/70 p-4">
          <div class="text-xs text-slate-400 font-medium">Only in Source</div>
          <div id="cntSrcOnly" class="text-3xl font-black text-blue-400 mt-1">0</div>
          <div class="text-[10px] text-slate-500 mt-1">Not published to npm</div>
        </div>
      </div>

      <!-- Findings Table Card -->
      <div class="rounded-2xl bg-surface-850 border border-surface-700/70 overflow-hidden shadow-xl">
        <div class="p-5 border-b border-surface-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>Discrepancy Findings</span>
              <span id="findingsCountBadge" class="text-xs font-mono px-2 py-0.5 rounded-full bg-surface-700 text-slate-300">0</span>
            </h3>
            <p class="text-xs text-slate-400">Classified diffs and risk signals detected by heuristic rules and LLM validation</p>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="downloadJsonReport()" class="px-3 py-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-300 border border-surface-700 text-xs font-mono transition">
              💾 Export JSON
            </button>
            <a href="/report.html" target="_blank" class="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono transition">
              ↗ Standalone HTML
            </a>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-surface-900/80 text-[11px] uppercase tracking-wider font-semibold text-slate-400 border-b border-surface-700">
              <tr>
                <th class="py-3 px-4">Risk</th>
                <th class="py-3 px-4">Classification</th>
                <th class="py-3 px-4">File Path</th>
                <th class="py-3 px-4">Signals Detected</th>
                <th class="py-3 px-4">Explanation & Evidence</th>
              </tr>
            </thead>
            <tbody id="findingsTableBody" class="divide-y divide-surface-750 font-sans">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Notes Accordion -->
      <div id="notesContainer" class="hidden rounded-xl bg-surface-850 border border-surface-700/60 p-4 text-xs font-mono text-slate-400">
        <div class="text-slate-200 font-semibold mb-1">Diagnostics / Pipeline Notes:</div>
        <ul id="notesList" class="list-disc list-inside space-y-1"></ul>
      </div>
    </div>
  </main>

  <!-- Evidence Modal -->
  <div id="evidenceModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-surface-850 border border-surface-700 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col overflow-hidden shadow-2xl">
      <div class="p-4 border-b border-surface-700 flex items-center justify-between">
        <div class="font-mono text-sm text-white font-semibold flex items-center gap-2">
          <span>Snippet / Evidence:</span>
          <span id="modalFilePath" class="text-cyan-400"></span>
        </div>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white text-lg p-1">&times;</button>
      </div>
      <div class="p-4 overflow-y-auto flex-1 font-mono text-xs bg-surface-900 text-rose-300">
        <pre id="modalContent" class="whitespace-pre-wrap leading-relaxed"></pre>
      </div>
      <div class="p-3 border-t border-surface-700 bg-surface-850 text-right">
        <button onclick="closeModal()" class="px-4 py-1.5 rounded-lg bg-surface-700 hover:bg-surface-600 text-white text-xs font-medium">Close</button>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="border-t border-surface-700/60 py-6 text-center text-xs text-slate-500">
    RepoLens &bull; Hacktoberfest Hack Day Sonipat (Problem 4) &bull; Team Sparrow: Rehan Hussain, Aadvik Gemini, Dhairya Agarwal
  </footer>

  <script>
    let currentReport = null;

    function setPackage(pkg, ver) {
      document.getElementById('pkgName').value = pkg;
      document.getElementById('pkgVersion').value = ver || '';
      document.getElementById('analyzeForm').requestSubmit();
    }

    function showStatus(msg, type = 'info') {
      const alert = document.getElementById('statusAlert');
      alert.classList.remove('hidden', 'bg-blue-950/60', 'text-blue-300', 'border-blue-800', 'bg-rose-950/60', 'text-rose-300', 'border-rose-800');
      if (type === 'error') {
        alert.classList.add('bg-rose-950/60', 'text-rose-300', 'border-rose-800');
      } else {
        alert.classList.add('bg-blue-950/60', 'text-blue-300', 'border-blue-800');
      }
      alert.textContent = msg;
    }

    function hideStatus() {
      document.getElementById('statusAlert').classList.add('hidden');
    }

    function setLoading(isLoading) {
      const btn = document.getElementById('submitBtn');
      const spinner = document.getElementById('btnSpinner');
      const text = document.getElementById('btnText');
      btn.disabled = isLoading;
      if (isLoading) {
        spinner.classList.remove('hidden');
        text.textContent = 'Analyzing Package...';
      } else {
        spinner.classList.add('hidden');
        text.textContent = 'Analyze Integrity';
      }
    }

    document.getElementById('analyzeForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const pkg = document.getElementById('pkgName').value.trim();
      const ver = document.getElementById('pkgVersion').value.trim();
      if (!pkg) return;

      setLoading(true);
      showStatus(`[RepoLens] Fetching ${pkg}${ver ? '@' + ver : ''} and cloning canonical source repo...`);

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: pkg, version: ver })
        });
        const data = await res.json();
        if (!res.ok || data.error) {
          throw new Error(data.error || 'Failed to analyze package');
        }
        renderReport(data.report);
        showStatus(`[RepoLens] Analysis complete for ${data.report.package_name}@${data.report.version}. Verdict: ${data.report.overall_verdict}`);
      } catch (err) {
        showStatus(`Error: ${err.message}`, 'error');
      } finally {
        setLoading(false);
      }
    });

    async function runSyntheticDemo() {
      setLoading(true);
      showStatus('[RepoLens] Running security analysis against Synthetic Tampered Fixture (Supply Chain Attack)...');
      try {
        const res = await fetch('/api/demo', { method: 'POST' });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Demo execution failed');
        renderReport(data.report);
        showStatus('[RepoLens] Synthetic Tampered Supply Chain Fixture analyzed! High-entropy payloads & malicious install hooks detected.', 'error');
      } catch (err) {
        showStatus(`Demo error: ${err.message}`, 'error');
      } finally {
        setLoading(false);
      }
    }

    function renderReport(report) {
      currentReport = report;
      document.getElementById('resultsSection').classList.remove('hidden');
      document.getElementById('viewHtmlBtn').classList.remove('hidden');

      // Package info
      document.getElementById('resPackageTarget').textContent = `${report.package_name}@${report.version}`;
      document.getElementById('resSourceRef').textContent = report.commit_or_tag || 'Not available / Synthetic';

      // Verdict styling
      const verdict = report.overall_verdict;
      const score = report.overall_risk_score;
      const vCard = document.getElementById('verdictCard');
      const vBadge = document.getElementById('verdictBadge');
      const vTitle = document.getElementById('verdictTitle');
      const vDesc = document.getElementById('verdictDesc');

      vCard.className = 'lg:col-span-2 rounded-2xl p-6 border flex flex-col justify-between transition-all ';
      if (verdict === 'CLEAN') {
        vCard.classList.add('bg-emerald-950/30', 'border-emerald-500/30', 'text-emerald-300');
        vBadge.className = 'text-xs font-bold px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        vBadge.textContent = 'VERIFIED CLEAN';
        vTitle.textContent = 'CLEAN INTEGRITY';
        vDesc.textContent = 'The published npm package matches the canonical git source code. No suspicious payloads or dangerous lifecycle scripts were introduced.';
      } else if (verdict === 'WARNING') {
        vCard.classList.add('bg-amber-950/30', 'border-amber-500/30', 'text-amber-300');
        vBadge.className = 'text-xs font-bold px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30';
        vBadge.textContent = 'ATTENTION REQUIRED';
        vTitle.textContent = 'WARNING: UNEXPLAINED DIFFS';
        vDesc.textContent = 'Discrepancies exist between package and source repository (e.g. build artifacts without verifiable maps or extra files), though no critical attack signals were verified.';
      } else {
        vCard.classList.add('bg-rose-950/30', 'border-rose-500/30', 'text-rose-300');
        vBadge.className = 'text-xs font-bold px-3 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30';
        vBadge.textContent = 'SUSPICIOUS / HIGH RISK';
        vTitle.textContent = 'CRITICAL: SUSPICIOUS PACKAGE';
        vDesc.textContent = 'HIGH-RISK SIGNALS DETECTED! Possible supply-chain tampering, unauthorized install hooks, high-entropy payloads, or unauthorized code execution.';
      }

      // Risk score gauge
      document.getElementById('scoreText').textContent = score;
      const ring = document.getElementById('scoreRing');
      const circumference = 2 * Math.PI * 50; // ~314.16
      const offset = circumference - (score / 100) * circumference;
      ring.style.strokeDashoffset = offset;

      const scoreLabel = document.getElementById('scoreLabel');
      if (score < 25) {
        ring.className = 'text-emerald-400';
        scoreLabel.className = 'text-xs font-semibold px-3 py-1 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        scoreLabel.textContent = 'LOW RISK';
      } else if (score < 60) {
        ring.className = 'text-amber-400';
        scoreLabel.className = 'text-xs font-semibold px-3 py-1 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30';
        scoreLabel.textContent = 'MODERATE RISK';
      } else {
        ring.className = 'text-rose-500';
        scoreLabel.className = 'text-xs font-semibold px-3 py-1 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30';
        scoreLabel.textContent = 'ELEVATED / HIGH RISK';
      }

      // File counts
      const counts = (report.metadata && report.metadata.file_counts) || { identical: 0, modified: 0, only_in_package: 0, only_in_source: 0 };
      document.getElementById('cntIdentical').textContent = counts.identical || 0;
      document.getElementById('cntModified').textContent = counts.modified || 0;
      document.getElementById('cntPkgOnly').textContent = counts.only_in_package || 0;
      document.getElementById('cntSrcOnly').textContent = counts.only_in_source || 0;

      // Findings
      const findings = report.findings || [];
      document.getElementById('findingsCountBadge').textContent = findings.length;
      const tbody = document.getElementById('findingsTableBody');
      tbody.innerHTML = '';

      if (findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-500">No discrepancies detected between package and source!</td></tr>`;
      } else {
        findings.forEach((f, idx) => {
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-surface-800/50 transition-colors';

          let riskBadgeClass = 'bg-slate-800 text-slate-400 border-slate-700';
          if (f.risk_level === 'HIGH') riskBadgeClass = 'bg-rose-500/20 text-rose-400 border-rose-500/40';
          else if (f.risk_level === 'MEDIUM') riskBadgeClass = 'bg-amber-500/20 text-amber-400 border-amber-500/40';

          let classColor = 'text-emerald-400';
          if (f.classification === 'SUSPICIOUS') classColor = 'text-rose-400 font-semibold';
          else if (f.classification === 'UNEXPLAINED') classColor = 'text-amber-400';

          const sigsHtml = (f.signals && f.signals.length)
            ? f.signals.map(s => `<span class="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-mono">${escapeHtml(s)}</span>`).join(' ')
            : `<span class="text-slate-500 text-xs">—</span>`;

          const evidenceBtn = f.evidence 
            ? `<button onclick="openModal('${escapeHtml(f.file_path)}', ${idx})" class="mt-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono underline block">View Evidence Snippet</button>`
            : '';

          tr.innerHTML = `
            <td class="py-3 px-4 align-top">
              <span class="px-2 py-0.5 rounded text-[11px] font-bold border ${riskBadgeClass}">${f.risk_level}</span>
            </td>
            <td class="py-3 px-4 align-top font-mono text-xs ${classColor}">
              ${escapeHtml(f.classification)}
            </td>
            <td class="py-3 px-4 align-top font-mono text-xs text-white max-w-[220px] truncate" title="${escapeHtml(f.file_path)}">
              ${escapeHtml(f.file_path)}
            </td>
            <td class="py-3 px-4 align-top">
              <div class="flex flex-wrap gap-1">${sigsHtml}</div>
            </td>
            <td class="py-3 px-4 align-top text-xs max-w-md">
              <div class="text-slate-300 leading-relaxed">${escapeHtml(f.explanation || '')}</div>
              ${evidenceBtn}
            </td>
          `;
          tbody.appendChild(tr);
        });
      }

      // Diagnostics
      const notes = (report.metadata && report.metadata.notes) || [];
      const notesContainer = document.getElementById('notesContainer');
      const notesList = document.getElementById('notesList');
      if (notes.length) {
        notesContainer.classList.remove('hidden');
        notesList.innerHTML = notes.map(n => `<li>${escapeHtml(n)}</li>`).join('');
      } else {
        notesContainer.classList.add('hidden');
      }

      // Smooth scroll to results
      document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }

    function openModal(filePath, findingIdx) {
      const f = currentReport && currentReport.findings && currentReport.findings[findingIdx];
      if (!f) return;
      document.getElementById('modalFilePath').textContent = filePath;
      document.getElementById('modalContent').textContent = f.evidence || 'No evidence snippet available.';
      document.getElementById('evidenceModal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('evidenceModal').classList.add('hidden');
    }

    function downloadJsonReport() {
      if (!currentReport) return;
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `repolens-${currentReport.package_name}-${currentReport.version}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
  </script>
</body>
</html>
"""


class RepoLensHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for RepoLens web server."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress noisy default request logs; write concise output."""
        sys.stderr.write(f"[RepoLens Web] {self.command} {self.path} - {args[1]}\n")

    def send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        global _LATEST_REPORT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            payload = HTML_DASHBOARD.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/status":
            self.send_json(200, {
                "status": "online",
                "version": "0.1.0",
                "team": "Sparrow",
                "problem": "Problem 4: Published Package vs Source Code Integrity Analyzer"
            })
            return

        if path == "/report.html":
            if _LATEST_REPORT:
                html = generate_html_report(_LATEST_REPORT)
            else:
                html = "<html><body><h3>No report generated yet. Run an analysis first.</h3></body></html>"
            payload = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/report.json":
            if _LATEST_REPORT:
                self.send_json(200, dataclasses.asdict(_LATEST_REPORT))
            else:
                self.send_json(404, {"error": "No report generated yet."})
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        global _LATEST_REPORT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/demo":
            # Run synthetic tampered fixture
            workdir = tempfile.mkdtemp(prefix="repolens_demo_")
            try:
                fixture_dir = tempfile.mkdtemp(prefix="repolens_fixture_")
                fx = make_tampered_fixture(fixture_dir)
                tgz = os.path.join(fixture_dir, "tampered-pkg.tgz")
                with tarfile.open(tgz, "w:gz") as tf:
                    for item in os.listdir(fx["package_dir"]):
                        p = os.path.join(fx["package_dir"], item)
                        tf.add(p, arcname="package/" + item)

                report = run_pipeline(None, None, workdir, tarball=tgz, source_dir=str(fx["source_dir"]))
                _LATEST_REPORT = report
                self.send_json(200, {"report": dataclasses.asdict(report)})
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
            return

        if path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length)
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except Exception:
                self.send_json(400, {"error": "Invalid JSON body"})
                return

            package = body.get("package", "").strip()
            version = body.get("version", "").strip() or None
            repo_url = body.get("repo_url", "").strip() or None

            if not package:
                self.send_json(400, {"error": "Package name is required"})
                return

            workdir = tempfile.mkdtemp(prefix="repolens_web_")
            try:
                report = run_pipeline(package, version, workdir, repo_url=repo_url)
                _LATEST_REPORT = report
                self.send_json(200, {"report": dataclasses.asdict(report)})
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
            return

        self.send_response(404)
        self.end_headers()


def start_server(port: int = DEFAULT_PORT) -> socketserver.TCPServer:
    """Start the RepoLens web dashboard server."""
    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("0.0.0.0", port), RepoLensHandler)
    print(f"[RepoLens] Localhost web server started at: http://localhost:{port}")
    return server


if __name__ == "__main__":
    port = DEFAULT_PORT
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    server = start_server(port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[RepoLens] Shutting down web server...")
        server.server_close()
