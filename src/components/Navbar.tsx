import React from 'react';
import { Shield, BookOpen, History, Terminal, Zap, ExternalLink } from 'lucide-react';

interface Props {
  historyCount: number;
  onOpenHistory: () => void;
  onOpenOwaspMatrix: () => void;
  onOpenSimulator: () => void;
  hasAuditResult: boolean;
}

export const Navbar: React.FC<Props> = ({
  historyCount,
  onOpenHistory,
  onOpenOwaspMatrix,
  onOpenSimulator,
  hasAuditResult,
}) => {
  return (
    <header className="border-b border-slate-800 bg-[#0d131f]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/30 to-purple-600/20 border border-cyan-500/40 shadow-lg shadow-cyan-950/50">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-[#0d131f] animate-ping" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-[#0d131f]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg text-slate-100 tracking-tight flex items-center gap-1 font-mono">
                SECULENS<span className="text-cyan-400 font-sans">.io</span>
              </span>
              <span className="px-2 py-0.5 text-[10px] uppercase font-mono font-bold tracking-wider rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700/50">
                AUDITOR PRO
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Cybersecurity Auditor & Code Vulnerability Analyzer
            </p>
          </div>
        </div>

        {/* Engine status indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/80 border border-slate-700/60 text-xs text-slate-300 font-mono">
          <Zap className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Core:</span>
          <span className="text-cyan-300 font-semibold">Gemini 3.8 Flash</span>
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        </div>

        {/* Navigation & Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {hasAuditResult && (
            <button
              onClick={onOpenSimulator}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/30 transition-colors shadow-sm"
              title="Test payload against vulnerable vs patched code"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exploit Sandbox</span>
            </button>
          )}

          <button
            onClick={onOpenOwaspMatrix}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 transition-colors"
          >
            <BookOpen className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">OWASP Top 10</span>
          </button>

          <button
            onClick={onOpenHistory}
            className="relative inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 transition-colors"
          >
            <History className="w-3.5 h-3.5 text-slate-400" />
            <span>History</span>
            {historyCount > 0 && (
              <span className="ml-0.5 px-1.5 py-0.2 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold">
                {historyCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
