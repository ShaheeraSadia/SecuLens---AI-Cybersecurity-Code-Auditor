import React, { useRef, useState } from 'react';
import {
  Code2,
  Globe,
  FileText,
  Upload,
  Copy,
  Trash2,
  Play,
  Loader2,
  Sparkles,
  ChevronDown,
  ChevronUp,
  FileCode,
  Check,
} from 'lucide-react';

interface Props {
  inputType: 'code' | 'http' | 'log';
  setInputType: (type: 'code' | 'http' | 'log') => void;
  targetEnvironment: string;
  setTargetEnvironment: (env: string) => void;
  content: string;
  setContent: (content: string) => void;
  contextNotes: string;
  setContextNotes: (notes: string) => void;
  onAudit: () => void;
  isLoading: boolean;
}

const ENVIRONMENTS = [
  'Node.js / Express / Fastify',
  'React / Next.js (App Router & Pages)',
  'Python / FastAPI / Django / Flask',
  'PostgreSQL / MySQL / SQLite (SQL)',
  'Go / Gin / Echo',
  'PHP / Laravel / WordPress',
  'Ruby on Rails',
  'Java / Spring Boot',
  'HTTP / REST API Payload',
  'Nginx / Apache Server Log',
  'Custom / Generic Environment',
];

export const CodeInputEditor: React.FC<Props> = ({
  inputType,
  setInputType,
  targetEnvironment,
  setTargetEnvironment,
  content,
  setContent,
  contextNotes,
  setContextNotes,
  onAudit,
  isLoading,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copied, setCopied] = useState(false);

  // File upload handler
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setContent(text);
        // Auto detect input type based on extension
        const ext = file.name.split('.').pop()?.toLowerCase();
        if (ext === 'log') {
          setInputType('log');
        } else if (ext === 'http') {
          setInputType('http');
        } else {
          setInputType('code');
        }
      }
    };
    reader.readAsText(file);
  };

  const handleCopyInput = async () => {
    if (!content) return;
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setContent(text);
    } catch {
      // Ignore clipboard read denial
    }
  };

  const lines = content.split('\n');
  const lineCount = lines.length;

  return (
    <div className="bg-[#0f172a]/95 rounded-2xl border border-slate-800 shadow-xl overflow-hidden flex flex-col">
      {/* Top Controls Bar */}
      <div className="p-3 sm:p-4 border-b border-slate-800 bg-slate-900/60 flex flex-wrap items-center justify-between gap-3">
        {/* Mode Selector Tabs */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            type="button"
            onClick={() => setInputType('code')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              inputType === 'code'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Code Snippet</span>
          </button>
          <button
            type="button"
            onClick={() => setInputType('http')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              inputType === 'http'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>HTTP Payload</span>
          </button>
          <button
            type="button"
            onClick={() => setInputType('log')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              inputType === 'log'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Server Log</span>
          </button>
        </div>

        {/* Environment Picker */}
        <div className="flex items-center gap-2">
          <label className="text-xs font-mono text-slate-400 hidden sm:inline">Env:</label>
          <select
            value={targetEnvironment}
            onChange={(e) => setTargetEnvironment(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 font-mono focus:outline-none focus:border-cyan-500"
          >
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {env}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Editor Main Canvas */}
      <div className="relative flex flex-1 min-h-[340px] max-h-[500px] overflow-hidden bg-[#090d16] font-mono text-xs">
        {/* Line Numbers gutter */}
        <div className="w-12 bg-[#0b101c] py-3 text-right pr-3 select-none text-slate-600 border-r border-slate-800/80 font-mono hidden sm:block overflow-hidden">
          {Array.from({ length: Math.max(1, Math.min(lineCount, 300)) }).map((_, i) => (
            <div key={i} className="leading-6">
              {i + 1}
            </div>
          ))}
        </div>

        {/* Textarea */}
        <div className="relative flex-1 flex flex-col">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={
              inputType === 'code'
                ? `// Paste your React, Next.js, Node.js, Express, SQL, or backend code snippet here...
// SecuLens will perform deep static analysis for OWASP Top 10 vulnerabilities,
// injection flaws, SSRF, unsanitized inputs, and generate secure patches.`
                : inputType === 'http'
                ? `// Paste raw HTTP request header & body or JSON payload...
POST /api/v1/auth/login HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"username": "' OR 1=1--", "password": "password"}`
                : `// Paste server access logs or authorization audit logs here...
192.168.1.100 - - [11/Oct/2026:10:00:00] "GET /download?file=../../etc/passwd" 200 1204`
            }
            className="w-full h-full p-3 leading-6 bg-transparent text-slate-200 font-mono text-xs sm:text-sm resize-none focus:outline-none focus:ring-0 selection:bg-cyan-500/30 placeholder:text-slate-600"
            spellCheck={false}
          />

          {/* Quick editor actions floating top right */}
          <div className="absolute top-2 right-2 flex items-center gap-1.5 bg-slate-900/90 backdrop-blur-md px-2 py-1 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={handlePasteClipboard}
              className="text-slate-400 hover:text-slate-200 p-1 text-[11px] flex items-center gap-1"
              title="Paste from clipboard"
            >
              Paste
            </button>
            <span className="text-slate-700">|</span>
            <button
              type="button"
              onClick={handleCopyInput}
              className="text-slate-400 hover:text-slate-200 p-1 text-[11px] flex items-center gap-1"
              title="Copy current content"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
            <span className="text-slate-700">|</span>
            <button
              type="button"
              onClick={() => setContent('')}
              className="text-slate-400 hover:text-rose-400 p-1 text-[11px]"
              title="Clear input"
            >
              <Trash2 className="w-3 h-3" />
            </button>
            <span className="text-slate-700">|</span>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              className="hidden"
              accept=".js,.ts,.tsx,.jsx,.py,.sql,.json,.log,.txt,.http,.env"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="text-slate-400 hover:text-cyan-400 p-1 text-[11px] flex items-center gap-1"
              title="Upload file (.ts, .tsx, .js, .py, .sql, .log)"
            >
              <Upload className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Advanced Context Drawer Toggle */}
      <div className="border-t border-slate-800/80 bg-slate-900/40 px-4 py-2 flex flex-col gap-2">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 self-start font-mono"
        >
          {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          <span>{showAdvanced ? 'Hide Attack Surface Context' : 'Add Attack Surface Context / Threat Model (Optional)'}</span>
        </button>

        {showAdvanced && (
          <div className="mt-1 pb-1">
            <textarea
              value={contextNotes}
              onChange={(e) => setContextNotes(e.target.value)}
              placeholder="e.g., 'This is a public-facing API endpoint accessible without JWT auth behind an AWS ALB' or 'Internal microservice communicating over gRPC'..."
              rows={2}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
        )}
      </div>

      {/* Bottom Action Footer */}
      <div className="p-3 sm:p-4 border-t border-slate-800 bg-slate-900/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400">
          <span>{lineCount} lines</span>
          <span>•</span>
          <span
            className={
              content.length > 10000
                ? 'text-rose-400 font-bold'
                : content.length > 8000
                ? 'text-amber-400 font-medium'
                : 'text-slate-400'
            }
          >
            {content.length.toLocaleString()} / 10,000 max chars
          </span>
          <span>•</span>
          <span className="text-cyan-400/90 hidden sm:inline">Rate Limit: 15/min</span>
        </div>

        <button
          type="button"
          onClick={onAudit}
          disabled={isLoading || !content.trim() || content.length > 10000}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold font-mono text-xs sm:text-sm tracking-wider uppercase transition-all shadow-lg ${
            isLoading || !content.trim() || content.length > 10000
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-cyan-500/25 border border-cyan-300/40 hover:scale-[1.01] active:scale-[0.99]'
          }`}
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
              <span>Analyzing Threat Vectors...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Run Security Audit</span>
              <Sparkles className="w-3.5 h-3.5 text-slate-950" />
            </>
          )}
        </button>
      </div>
    </div>
  );
};
