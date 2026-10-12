import React from 'react';
import { X, ShieldAlert, CheckCircle2, ExternalLink, BookOpen } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

const OWASP_CATEGORIES = [
  {
    code: 'A01:2021',
    name: 'Broken Access Control',
    cwe: 'CWE-284, CWE-22, CWE-639',
    description: 'Failures where users can act outside their intended permissions, leading to unauthorized information disclosure or modification (e.g. IDOR, path traversal).',
    defense: 'Deny by default, enforce record ownership on every request, disable directory browsing, rate-limit API endpoints.',
  },
  {
    code: 'A02:2021',
    name: 'Cryptographic Failures',
    cwe: 'CWE-259, CWE-327, CWE-331',
    description: 'Use of weak cipher suites, hardcoded credentials, cleartext transmission of sensitive data (passwords, tokens, PII).',
    defense: 'Use TLS 1.3, Argon2id/bcrypt for passwords, encrypt data at rest with AES-GCM-256, disable legacy protocols.',
  },
  {
    code: 'A03:2021',
    name: 'Injection (SQL, NoSQL, XSS, Command)',
    cwe: 'CWE-89, CWE-79, CWE-77, CWE-94',
    description: 'Hostile data sent to an interpreter as part of a command or query, tricking the interpreter into executing unintended instructions.',
    defense: 'Use parameterized queries (prepared statements), context-aware output encoding (DOMPurify), ORM query builders, input schemas.',
  },
  {
    code: 'A04:2021',
    name: 'Insecure Design',
    cwe: 'CWE-209, CWE-256, CWE-501',
    description: 'Missing or ineffective security controls at the architecture stage, such as lack of threat modeling or business logic flaws.',
    defense: 'Implement threat modeling (STRIDE), secure design patterns, principle of least privilege, unit tests for abuse cases.',
  },
  {
    code: 'A05:2021',
    name: 'Security Misconfiguration',
    cwe: 'CWE-16, CWE-200, CWE-1004',
    description: 'Unnecessary features enabled, default accounts/passwords, overly permissive CORS headers, or verbose stack traces in production.',
    defense: 'Harden environments with automated configs, use security headers (Helmet, CSP, HSTS), disable debug modes in production.',
  },
  {
    code: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    cwe: 'CWE-1104, CWE-937',
    description: 'Using dependencies with known CVEs without continuous vulnerability monitoring or automated patch updates.',
    defense: 'Run npm audit / Snyk / Dependabot in CI/CD, lock dependency versions, remove unused packages.',
  },
  {
    code: 'A07:2021',
    name: 'Identification and Authentication Failures',
    cwe: 'CWE-287, CWE-384, CWE-613',
    description: 'Weak session management, credential stuffing vulnerability, absence of multi-factor authentication (MFA).',
    defense: 'Implement MFA, rate limit login attempts, use secure HTTP-only SameSite cookies, rotate session tokens on privilege change.',
  },
  {
    code: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    cwe: 'CWE-494, CWE-502, CWE-829',
    description: 'Code and infrastructure that do not protect against integrity violations, untrusted CI/CD pipelines, or insecure deserialization.',
    defense: 'Sign artifacts, verify npm package hashes, reject untrusted object deserialization, enforce review for all pull requests.',
  },
  {
    code: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    cwe: 'CWE-778, CWE-117',
    description: 'Insufficient logging of critical events (logins, failed auth, access control denials) allowing breaches to go unnoticed.',
    defense: 'Log all authentication & authorization events, forward to centralized SIEM, sanitize logs to prevent log injection (CRLF).',
  },
  {
    code: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    cwe: 'CWE-918',
    description: 'Web application fetches a remote resource without validating the user-supplied URL, letting attackers probe cloud metadata or internal VPCs.',
    defense: 'Strictly allowlist schemes (http/https), reject loopback & link-local IPs (127.0.0.1, 169.254.169.254, 10.0.0.0/8), disable HTTP redirects.',
  },
];

export const OwaspReferenceModal: React.FC<Props> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-mono">
                OWASP Top 10 Reference Matrix
              </h3>
              <p className="text-xs text-slate-400">
                Official security standards and defensive architectures evaluated by SecuLens
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OWASP_CATEGORIES.map((cat) => (
              <div
                key={cat.code}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40">
                      {cat.code}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">{cat.cwe}</span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-200 mb-1.5">{cat.name}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed mb-3">
                    {cat.description}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-900 text-xs">
                  <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider block mb-0.5">
                    Hardening Defense:
                  </span>
                  <p className="text-slate-300 text-[11px]">{cat.defense}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium transition-colors"
          >
            Close Reference
          </button>
        </div>
      </div>
    </div>
  );
};
