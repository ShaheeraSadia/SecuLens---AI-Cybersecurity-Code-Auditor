import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Code2,
  FileCheck2,
  BookCheck,
  Copy,
  Check,
  Download,
  Terminal,
  ExternalLink,
  ChevronRight,
  Shield,
  Layers,
  Sparkles,
} from 'lucide-react';
import { AuditResult } from '../types/security';
import { VulnerabilityBadge } from './VulnerabilityBadge';

interface Props {
  audit: AuditResult;
  originalCode: string;
  onOpenSimulator: () => void;
}

export const AuditReportView: React.FC<Props> = ({
  audit,
  originalCode,
  onOpenSimulator,
}) => {
  const [activeTab, setActiveTab] = useState<'assessment' | 'flaws' | 'patch' | 'owasp'>('assessment');
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [patchViewMode, setPatchViewMode] = useState<'secured' | 'diff'>('secured');

  const handleCopyPatch = async () => {
    if (!audit.patchedCode) return;
    await navigator.clipboard.writeText(audit.patchedCode);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  const handleExportMarkdown = () => {
    const md = `# SecuLens Security Audit Report
Generated: ${new Date().toISOString()}

## 1. Vulnerability Assessment
- **Status:** ${audit.riskLevel}
- **CVSS v3.1 Score:** ${audit.cvssScore} / 10.0
- **CWE Identifier:** ${audit.cweId}
- **OWASP Category:** ${audit.owaspCategory}

### Executive Verdict
${audit.executiveSummary}

---

## 2. Identified Security Flaws
${
  audit.identifiedFlaws.length === 0
    ? 'No security flaws or vulnerabilities were detected in the submitted input.'
    : audit.identifiedFlaws
        .map(
          (flaw, idx) => `
### Flaw #${idx + 1}: ${flaw.title} (${flaw.severity})
- **Threat Mechanism:** ${flaw.threatMechanism}
- **Exploitation Scenario:** ${flaw.exploitationScenario}
- **Affected Input:** \`${flaw.affectedCodeOrInput || 'N/A'}\`
- **Impact (CIA):** ${flaw.impact}
`
        )
        .join('\n')
}

---

## 3. Patched & Secured Code Version (${audit.patchLanguage})
\`\`\`${audit.patchLanguage}
${audit.patchedCode}
\`\`\`

### Patch Rationale
${audit.patchExplanation}

---

## 4. OWASP Recommendations
${audit.owaspRecommendations
  .map(
    (rec) => `
- **[${rec.category}]**: ${rec.guideline}
  *Rationale:* ${rec.rationale}
`
  )
  .join('\n')}

${
  audit.automatedDefenseRule
    ? `\n### CI/CD Defense Rule (ESLint / Semgrep / WAF)\n\`\`\`yaml\n${audit.automatedDefenseRule}\n\`\`\`\n`
    : ''
}
`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `seculens-audit-${Date.now()}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const isSafe = audit.riskLevel === 'Safe';

  return (
    <div className="bg-[#0f172a] rounded-2xl border border-slate-800 shadow-2xl overflow-hidden flex flex-col">
      {/* Audit Banner / Top Scorecard */}
      <div className="p-4 sm:p-6 border-b border-slate-800 bg-gradient-to-r from-slate-900 via-[#101726] to-slate-900">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <VulnerabilityBadge riskLevel={audit.riskLevel} size="lg" />
              <span className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-300">
                {audit.cweId}
              </span>
              <span className="text-xs font-mono px-2.5 py-1 rounded-md bg-cyan-950/60 border border-cyan-800/40 text-cyan-300">
                {audit.owaspCategory}
              </span>
            </div>
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed mt-1 font-medium">
              {audit.executiveSummary}
            </p>
          </div>

          {/* CVSS Metric Gauge */}
          <div className="flex items-center gap-3 sm:gap-4 bg-slate-950/80 p-3 sm:p-4 rounded-xl border border-slate-800 self-start md:self-auto shrink-0">
            <div className="text-right font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-widest block font-bold">
                CVSS v3.1
              </span>
              <div className="flex items-baseline gap-1 justify-end">
                <span
                  className={`text-2xl sm:text-3xl font-extrabold ${
                    audit.cvssScore >= 9.0
                      ? 'text-red-400'
                      : audit.cvssScore >= 7.0
                      ? 'text-rose-400'
                      : audit.cvssScore >= 4.0
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {audit.cvssScore.toFixed(1)}
                </span>
                <span className="text-xs text-slate-500">/10</span>
              </div>
            </div>

            <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden self-center">
              <div
                className={`h-full rounded-full transition-all duration-700 ${
                  audit.cvssScore >= 9.0
                    ? 'bg-red-500'
                    : audit.cvssScore >= 7.0
                    ? 'bg-rose-500'
                    : audit.cvssScore >= 4.0
                    ? 'bg-amber-400'
                    : 'bg-emerald-400'
                }`}
                style={{ width: `${Math.max(5, (audit.cvssScore / 10) * 100)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Action Row */}
        <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">
              Audited components: <strong className="text-slate-200">{audit.identifiedFlaws.length} flaws</strong> detected
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onOpenSimulator}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/50 transition-colors"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Simulate Attack</span>
            </button>

            <button
              onClick={handleExportMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
              title="Download detailed Markdown report"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export Report</span>
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex items-center border-b border-slate-800 bg-[#0b101c] px-3 sm:px-6 overflow-x-auto">
        <button
          onClick={() => setActiveTab('assessment')}
          className={`flex items-center gap-2 py-3 px-3 border-b-2 text-xs sm:text-sm font-mono font-medium transition-colors shrink-0 ${
            activeTab === 'assessment'
              ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>1. Assessment</span>
        </button>

        <button
          onClick={() => setActiveTab('flaws')}
          className={`flex items-center gap-2 py-3 px-3 border-b-2 text-xs sm:text-sm font-mono font-medium transition-colors shrink-0 ${
            activeTab === 'flaws'
              ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>2. Security Flaws ({audit.identifiedFlaws.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('patch')}
          className={`flex items-center gap-2 py-3 px-3 border-b-2 text-xs sm:text-sm font-mono font-medium transition-colors shrink-0 ${
            activeTab === 'patch'
              ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>3. Patched Code</span>
        </button>

        <button
          onClick={() => setActiveTab('owasp')}
          className={`flex items-center gap-2 py-3 px-3 border-b-2 text-xs sm:text-sm font-mono font-medium transition-colors shrink-0 ${
            activeTab === 'owasp'
              ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <BookCheck className="w-4 h-4" />
          <span>4. OWASP Recommendations</span>
        </button>
      </div>

      {/* Tab 1: Vulnerability Assessment */}
      {activeTab === 'assessment' && (
        <div className="p-4 sm:p-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Risk Classification
              </span>
              <div className="flex items-center gap-2 mt-1">
                <VulnerabilityBadge riskLevel={audit.riskLevel} size="md" />
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Evaluated against OWASP risk severity criteria and CVSS metrics.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                CWE Standard Reference
              </span>
              <p className="text-sm font-bold text-slate-200 font-mono mt-1">
                {audit.cweId}
              </p>
              <p className="text-xs text-slate-400 mt-2">
                MITRE Common Weakness Enumeration classification.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                OWASP Top 10 Taxonomy
              </span>
              <p className="text-sm font-bold text-cyan-300 font-mono mt-1">
                {audit.owaspCategory}
              </p>
              <p className="text-xs text-slate-400 mt-2">
                Primary threat classification under industry standards.
              </p>
            </div>
          </div>

          {/* Assessment Narrative */}
          <div className="p-5 rounded-xl bg-slate-950 border border-slate-800">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              Auditor Executive Evaluation
            </h4>
            <div className="text-sm text-slate-300 leading-relaxed space-y-3 font-sans">
              <p>{audit.executiveSummary}</p>
              {isSafe ? (
                <div className="p-3 rounded-lg bg-emerald-950/50 border border-emerald-800/50 text-emerald-300 text-xs flex items-start gap-2.5">
                  <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <strong>Secure Implementation Confirmed:</strong> The submitted code demonstrates proper parameterization, input sanitization, or defensive controls that neutralize common exploitation vectors.
                  </div>
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/40 text-rose-300 text-xs flex items-start gap-2.5">
                  <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <strong>Remediation Required Before Production:</strong> Identified {audit.identifiedFlaws.length} security flaw(s) that could allow malicious actors to compromise confidentiality, integrity, or system boundaries. Apply the patched code in Tab 3.
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Quick Flaw Previews if any */}
          {audit.identifiedFlaws.length > 0 && (
            <div>
              <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">
                Identified Attack Vectors ({audit.identifiedFlaws.length})
              </h4>
              <div className="space-y-3">
                {audit.identifiedFlaws.map((flaw, idx) => (
                  <div
                    key={idx}
                    onClick={() => setActiveTab('flaws')}
                    className="p-3.5 rounded-xl bg-slate-950/50 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 transition-all cursor-pointer flex items-center justify-between gap-3"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-md bg-slate-800 text-slate-300 text-xs font-mono flex items-center justify-center font-bold">
                        {idx + 1}
                      </span>
                      <div>
                        <span className="text-sm font-semibold text-slate-200">
                          {flaw.title}
                        </span>
                        <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                          {flaw.threatMechanism}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/50">
                        {flaw.severity}
                      </span>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Identified Security Flaws */}
      {activeTab === 'flaws' && (
        <div className="p-4 sm:p-6 space-y-6">
          {audit.identifiedFlaws.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-slate-950 border border-slate-800">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-base font-bold text-slate-200">
                No Security Flaws Detected
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                The input does not contain identifiable vulnerabilities matching OWASP Top 10, injection signatures, or insecure pattern heuristics.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {audit.identifiedFlaws.map((flaw, index) => (
                <div
                  key={index}
                  className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-md"
                >
                  <div className="p-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/40 text-xs font-mono font-bold flex items-center justify-center">
                        #{index + 1}
                      </span>
                      <h4 className="text-sm font-bold text-slate-100">
                        {flaw.title}
                      </h4>
                    </div>
                    <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800/80 font-bold">
                      {flaw.severity} SEVERITY
                    </span>
                  </div>

                  <div className="p-4 sm:p-5 space-y-4 text-xs sm:text-sm">
                    {/* Vulnerable input pointer */}
                    {flaw.affectedCodeOrInput && (
                      <div>
                        <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1 font-semibold">
                          Vulnerable Snippet / Parameter:
                        </span>
                        <div className="p-2.5 rounded-lg bg-[#070b13] border border-slate-800/80 font-mono text-rose-300 text-xs overflow-x-auto">
                          <code>{flaw.affectedCodeOrInput}</code>
                        </div>
                      </div>
                    )}

                    {/* Threat Mechanism */}
                    <div>
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1 font-semibold">
                        Threat Mechanism & Root Cause:
                      </span>
                      <p className="text-slate-300 leading-relaxed font-sans bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                        {flaw.threatMechanism}
                      </p>
                    </div>

                    {/* Exploitation Scenario */}
                    <div>
                      <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider block mb-1 font-semibold flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5" />
                        Attacker Exploitation Scenario & Payload:
                      </span>
                      <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/30 font-mono text-xs text-amber-200/90 whitespace-pre-wrap leading-relaxed">
                        {flaw.exploitationScenario}
                      </div>
                    </div>

                    {/* Impact */}
                    <div>
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1 font-semibold">
                        Impact on CIA Triad:
                      </span>
                      <p className="text-slate-300 leading-relaxed font-sans bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                        {flaw.impact}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Patched & Secured Code */}
      {activeTab === 'patch' && (
        <div className="p-4 sm:p-6 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                Hardened, Production-Ready Implementation
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Formatted in {audit.patchLanguage || 'TypeScript/Node.js'} with defense-in-depth sanitization applied.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
                <button
                  onClick={() => setPatchViewMode('secured')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    patchViewMode === 'secured'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Secured Code
                </button>
                <button
                  onClick={() => setPatchViewMode('diff')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    patchViewMode === 'diff'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Side-by-Side Compare
                </button>
              </div>

              <button
                onClick={handleCopyPatch}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-emerald-300 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 transition-colors shadow-sm"
              >
                {copiedPatch ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
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

          {/* Secured Code Box */}
          {patchViewMode === 'secured' ? (
            <div className="relative rounded-xl bg-[#070b13] border border-emerald-500/30 overflow-hidden shadow-xl">
              <div className="p-2.5 bg-slate-900/80 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  secured-patch.{audit.patchLanguage || 'ts'}
                </span>
                <span>Production Fortified</span>
              </div>
              <pre className="p-4 text-xs sm:text-sm font-mono text-slate-200 overflow-x-auto leading-relaxed select-text">
                <code>{audit.patchedCode}</code>
              </pre>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Original Code */}
              <div className="rounded-xl bg-[#070b13] border border-rose-500/30 overflow-hidden">
                <div className="p-2.5 bg-slate-900/80 border-b border-slate-800 text-xs font-mono text-rose-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-400" />
                  Original (Vulnerable)
                </div>
                <pre className="p-3 text-xs font-mono text-slate-300 overflow-x-auto max-h-[400px]">
                  <code>{originalCode}</code>
                </pre>
              </div>

              {/* Patched Code */}
              <div className="rounded-xl bg-[#070b13] border border-emerald-500/30 overflow-hidden">
                <div className="p-2.5 bg-slate-900/80 border-b border-slate-800 text-xs font-mono text-emerald-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  Patched (Secured)
                </div>
                <pre className="p-3 text-xs font-mono text-slate-200 overflow-x-auto max-h-[400px]">
                  <code>{audit.patchedCode}</code>
                </pre>
              </div>
            </div>
          )}

          {/* Patch Explanation */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2">
              Defensive Mechanism Rationale
            </h4>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              {audit.patchExplanation}
            </p>
          </div>
        </div>
      )}

      {/* Tab 4: OWASP Recommendations */}
      {activeTab === 'owasp' && (
        <div className="p-4 sm:p-6 space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <BookCheck className="w-4 h-4 text-cyan-400" />
              OWASP Prevention Best Practices & Hardening
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Standardized architectural countermeasures derived from the OWASP Cheat Sheet Series.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {audit.owaspRecommendations.map((rec, index) => (
              <div
                key={index}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
              >
                <div>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40 uppercase tracking-wider">
                    {rec.category}
                  </span>
                  <h4 className="text-sm font-bold text-slate-200 mt-2">
                    {rec.guideline}
                  </h4>
                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                    {rec.rationale}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Automated Defense Rule */}
          {audit.automatedDefenseRule && (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Automated CI/CD Rule (ESLint / Semgrep / WAF)
                </h4>
                <button
                  onClick={async () => {
                    await navigator.clipboard.writeText(audit.automatedDefenseRule || '');
                  }}
                  className="text-xs text-slate-400 hover:text-cyan-300 font-mono flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  <span>Copy Rule</span>
                </button>
              </div>
              <div className="p-3 rounded-lg bg-[#070b13] border border-slate-800/80 font-mono text-xs text-cyan-200/90 overflow-x-auto whitespace-pre-wrap">
                <code>{audit.automatedDefenseRule}</code>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                Integrate this rule into your GitHub Actions, pre-commit hooks, or SAST pipelines to prevent regression.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
