import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Play,
  Loader2,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Code2,
  FileCheck2,
  BookCheck,
  Split,
  Eye,
} from 'lucide-react';

const SAMPLE_VULNERABILITY = `// Express.js Login Controller
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Direct SQL string concatenation allows SQL Injection
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  const user = await db.query(query);

  if (user) {
    res.json({ success: true, token: createToken(user) });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});`;

export default function SecurityAnalyzerModule() {
  const [code, setCode] = useState(SAMPLE_VULNERABILITY);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [audit, setAudit] = useState(null);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState('diff'); // 'diff' | 'patched'
  const MAX_CODE_LENGTH = 10000;

  const handleScan = async () => {
    if (!code.trim() || loading) return;

    if (code.length > MAX_CODE_LENGTH) {
      setError(`Payload too large (${code.length.toLocaleString()} characters). Please keep input under 10,000 characters to prevent resource exhaustion.`);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Calls the /api/analyze-security endpoint
      const response = await fetch('/api/analyze-security', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code,
          inputType: 'code',
          targetEnvironment: 'Node.js / React / Next.js',
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.success) {
        if (response.status === 429) {
          throw new Error('Rate limit exceeded (15 scans per minute limit). Please wait 60 seconds before scanning again.');
        }
        if (response.status === 413) {
          throw new Error(`Payload too large (${code.length} characters). Maximum 10,000 characters allowed.`);
        }
        throw new Error(data.error || 'Failed to analyze code.');
      }

      setAudit(data.audit);
    } catch (err) {
      console.error('Scan Error:', err);
      setError(err.message || 'An error occurred during security scanning.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyPatched = async () => {
    if (!audit?.patchedCode) return;
    await navigator.clipboard.writeText(audit.patchedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getBadgeStyle = (level) => {
    switch (level) {
      case 'Safe':
        return {
          bg: 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400',
          dot: 'bg-emerald-400',
          icon: <ShieldCheck className="w-4 h-4" />,
          label: 'SAFE',
        };
      case 'Moderate Risk':
        return {
          bg: 'bg-amber-500/10 border-amber-500/40 text-amber-400',
          dot: 'bg-amber-400',
          icon: <AlertTriangle className="w-4 h-4" />,
          label: 'MODERATE RISK',
        };
      case 'High Risk':
        return {
          bg: 'bg-rose-500/10 border-rose-500/40 text-rose-400',
          dot: 'bg-rose-400',
          icon: <ShieldAlert className="w-4 h-4" />,
          label: 'HIGH RISK',
        };
      case 'Critical Risk':
      default:
        return {
          bg: 'bg-red-600/15 border-red-500/50 text-red-300',
          dot: 'bg-red-400',
          icon: <Flame className="w-4 h-4" />,
          label: 'CRITICAL RISK',
        };
    }
  };

  return (
    <div className="bg-[#0f172a] rounded-2xl border border-slate-800 shadow-2xl p-5 sm:p-7 space-y-6">
      {/* Module Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-base sm:text-lg font-bold font-mono text-slate-100">
              Security Analyzer Module
            </h2>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
              /api/analyze-security
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Submit code snippets to detect OWASP vulnerabilities (XSS, SQLi, SSRF, injection) and generate hardened patches.
          </p>
        </div>

        {/* Quick sample reset */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCode(SAMPLE_VULNERABILITY)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Load SQLi Sample</span>
          </button>
          <button
            type="button"
            onClick={() => setCode('')}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-400 hover:text-rose-400 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* 1. Input Box */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <label className="font-semibold text-slate-300 flex items-center gap-1.5">
            <Code2 className="w-4 h-4 text-cyan-400" />
            <span>Code Input Box</span>
          </label>
          <div className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-mono ${
                code.length > MAX_CODE_LENGTH
                  ? 'bg-rose-950 text-rose-300 border border-rose-800 font-bold'
                  : code.length > 8000
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'text-slate-400'
              }`}
            >
              {code.length.toLocaleString()} / {MAX_CODE_LENGTH.toLocaleString()} max chars
            </span>
          </div>
        </div>

        <div className={`relative rounded-xl border bg-[#090d16] overflow-hidden ${
          code.length > MAX_CODE_LENGTH ? 'border-rose-500/60 ring-1 ring-rose-500/40' : 'border-slate-800'
        }`}>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="// Paste Node.js, Express, React, Next.js, or SQL code here to scan for vulnerabilities..."
            rows={10}
            className="w-full p-4 bg-transparent text-slate-200 font-mono text-xs sm:text-sm resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed placeholder:text-slate-600"
            spellCheck={false}
          />
        </div>
      </div>

      {/* 2. Scan Button & Rate Limit Guard Info */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-cyan-300">
            🛡️ Server Hardened
          </span>
          <span className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
            Rate Limit: 15/min
          </span>
          <span className="hidden md:inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-emerald-400">
            Anti-Injection Active
          </span>
        </div>

        <button
          type="button"
          onClick={handleScan}
          disabled={loading || !code.trim() || code.length > MAX_CODE_LENGTH}
          className={`flex items-center gap-2 px-6 py-2.5 rounded-xl font-mono text-xs sm:text-sm font-bold uppercase tracking-wider transition-all shadow-lg ${
            loading || !code.trim() || code.length > MAX_CODE_LENGTH
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 border border-cyan-400/40 shadow-cyan-500/20 hover:scale-[1.01]'
          }`}
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-slate-300" />
              <span>Scanning Vulnerabilities...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Scan Code</span>
              <Sparkles className="w-3.5 h-3.5" />
            </>
          )}
        </button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
          <strong>Scan Error:</strong> {error}
        </div>
      )}

      {/* 3. Badge & Results Container */}
      {audit && (
        <div className="mt-6 pt-6 border-t border-slate-800 space-y-6">
          {/* Status Badge & Summary */}
          <div className="p-4 sm:p-5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                {/* Vulnerability Badge */}
                {(() => {
                  const style = getBadgeStyle(audit.riskLevel);
                  return (
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-mono font-bold uppercase tracking-wider ${style.bg}`}
                    >
                      {style.icon}
                      <span>{style.label}</span>
                      <span className={`w-1.5 h-1.5 rounded-full ${style.dot} animate-pulse`} />
                    </span>
                  );
                })()}

                <span className="px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700">
                  {audit.cweId}
                </span>

                <span className="px-2.5 py-0.5 rounded bg-cyan-950 text-cyan-300 text-xs font-mono border border-cyan-800">
                  {audit.owaspCategory}
                </span>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed font-sans">
                {audit.executiveSummary}
              </p>
            </div>

            {/* CVSS Metric */}
            <div className="bg-[#090d16] px-4 py-2.5 rounded-xl border border-slate-800 text-right font-mono self-start md:self-auto shrink-0">
              <span className="text-[10px] text-slate-400 block uppercase font-bold tracking-widest">
                CVSS Score
              </span>
              <span
                className={`text-2xl font-black ${
                  audit.cvssScore >= 7 ? 'text-rose-400' : audit.cvssScore >= 4 ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {audit.cvssScore.toFixed(1)}
              </span>
              <span className="text-xs text-slate-500"> / 10.0</span>
            </div>
          </div>

          {/* Identified Flaws List */}
          {audit.identifiedFlaws?.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                Identified Security Flaws
              </h3>
              <div className="grid grid-cols-1 gap-3">
                {audit.identifiedFlaws.map((flaw, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2 text-xs font-sans"
                  >
                    <div className="flex items-center justify-between">
                      <strong className="text-rose-300 font-mono text-sm">
                        #{idx + 1} {flaw.title}
                      </strong>
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono text-[10px] uppercase font-bold">
                        {flaw.severity}
                      </span>
                    </div>
                    <p className="text-slate-300 leading-relaxed">
                      {flaw.threatMechanism}
                    </p>
                    <div className="p-2 rounded bg-[#090d16] font-mono text-[11px] text-amber-300/90 border border-slate-800">
                      <strong>Exploit Scenario:</strong> {flaw.exploitationScenario}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 4. Diff / Patched Code Viewer */}
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs sm:text-sm font-bold font-mono text-slate-200">
                  Diff & Patched Code Viewer
                </h3>
              </div>

              <div className="flex items-center gap-2">
                {/* View Mode Toggle */}
                <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setViewMode('diff')}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded transition-colors ${
                      viewMode === 'diff'
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Split className="w-3.5 h-3.5" />
                    <span>Diff View</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewMode('patched')}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded transition-colors ${
                      viewMode === 'patched'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Patched Only</span>
                  </button>
                </div>

                {/* Copy Button */}
                <button
                  type="button"
                  onClick={handleCopyPatched}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-xs font-mono text-emerald-300 transition-colors shadow-sm"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Patched Code</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Viewer Display */}
            {viewMode === 'diff' ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Vulnerable Original */}
                <div className="rounded-xl border border-rose-500/30 bg-[#070b13] overflow-hidden">
                  <div className="px-3 py-2 bg-rose-950/40 border-b border-rose-900/40 text-xs font-mono text-rose-300 font-bold flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-400" />
                      Original (Vulnerable Code)
                    </span>
                    <span className="text-[10px] text-rose-400/80">Input</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-rose-200/90 overflow-x-auto max-h-[420px] leading-relaxed">
                    <code>{code}</code>
                  </pre>
                </div>

                {/* Secured Patched */}
                <div className="rounded-xl border border-emerald-500/30 bg-[#070b13] overflow-hidden">
                  <div className="px-3 py-2 bg-emerald-950/40 border-b border-emerald-900/40 text-xs font-mono text-emerald-300 font-bold flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      Patched (Secured Code)
                    </span>
                    <span className="text-[10px] text-emerald-400/80">Production Safe</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-emerald-200/90 overflow-x-auto max-h-[420px] leading-relaxed">
                    <code>{audit.patchedCode}</code>
                  </pre>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-emerald-500/40 bg-[#070b13] overflow-hidden shadow-xl">
                <div className="px-4 py-2.5 bg-emerald-950/30 border-b border-emerald-900/40 text-xs font-mono text-emerald-300 font-semibold flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    secured-patch.{audit.patchLanguage || 'js'}
                  </span>
                  <span>Ready to Deploy</span>
                </div>
                <pre className="p-5 text-xs sm:text-sm font-mono text-slate-200 overflow-x-auto leading-relaxed select-text">
                  <code>{audit.patchedCode}</code>
                </pre>
              </div>
            )}

            {/* Patch Explanation Note */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-1.5">
              <span className="font-mono font-bold text-cyan-300 block">
                Technical Defense Explanation:
              </span>
              <p className="leading-relaxed">{audit.patchExplanation}</p>
            </div>

            {/* OWASP Recommendations */}
            {audit.owaspRecommendations?.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-cyan-400 uppercase">
                  <BookCheck className="w-4 h-4" />
                  <span>OWASP Recommendations</span>
                </div>
                <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                  {audit.owaspRecommendations.map((rec, i) => (
                    <li key={i} className="leading-relaxed">
                      <strong className="text-slate-200">[{rec.category}]:</strong> {rec.guideline}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
