/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { PresetSelector } from './components/PresetSelector';
import { CodeInputEditor } from './components/CodeInputEditor';
import { AuditReportView } from './components/AuditReportView';
import { ExploitSimulatorModal } from './components/ExploitSimulatorModal';
import { OwaspReferenceModal } from './components/OwaspReferenceModal';
import { HistoryDrawer } from './components/HistoryDrawer';
import SecurityAnalyzerModule from './components/SecurityAnalyzerModule';
import { PRESET_SAMPLES } from './data/presets';
import { AuditResult, AuditHistoryItem, PresetSample } from './types/security';
import {
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  Terminal,
  Activity,
  CheckCircle2,
  Lock,
  Search,
} from 'lucide-react';

export default function App() {
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(PRESET_SAMPLES[0].id);
  const [inputType, setInputType] = useState<'code' | 'http' | 'log'>(PRESET_SAMPLES[0].inputType);
  const [targetEnvironment, setTargetEnvironment] = useState<string>(PRESET_SAMPLES[0].targetEnvironment);
  const [content, setContent] = useState<string>(PRESET_SAMPLES[0].code);
  const [contextNotes, setContextNotes] = useState<string>('');

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'module' | 'full'>('module');

  // Modals & Drawers
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isOwaspModalOpen, setIsOwaspModalOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [history, setHistory] = useState<AuditHistoryItem[]>([]);

  // Load history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('seculens_audit_history');
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // Ignore storage read errors
    }
  }, []);

  const saveToHistory = (result: AuditResult, inputTxt: string) => {
    try {
      const newItem: AuditHistoryItem = {
        id: 'scan-' + Date.now(),
        timestamp: Date.now(),
        inputType,
        targetEnvironment,
        title: result.cweId.replace(/^CWE-\d+:\s*/, '') || result.owaspCategory || 'Code Audit',
        snippetPreview: inputTxt.slice(0, 140).trim() + '...',
        inputContent: inputTxt,
        result,
      };

      const updated = [newItem, ...history.filter((h) => h.id !== newItem.id)].slice(0, 25);
      setHistory(updated);
      localStorage.setItem('seculens_audit_history', JSON.stringify(updated));
    } catch {
      // Ignore storage write errors
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('seculens_audit_history');
    } catch {
      // Ignore
    }
  };

  const handleSelectPreset = (preset: PresetSample) => {
    setSelectedPresetId(preset.id);
    setInputType(preset.inputType);
    setTargetEnvironment(preset.targetEnvironment);
    setContent(preset.code);
    setContextNotes('');
    setError(null);
  };

  const handleSelectHistoryItem = (item: AuditHistoryItem) => {
    setInputType(item.inputType);
    setTargetEnvironment(item.targetEnvironment);
    setContent(item.inputContent);
    setAuditResult(item.result);
    setSelectedPresetId(null);
    setError(null);
  };

  const runAudit = async () => {
    if (!content.trim() || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          inputType,
          targetEnvironment,
          content,
          contextNotes,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok || !data.success) {
        if (res.status === 429) {
          throw new Error('Rate limit exceeded (15 scans per minute limit). Please wait 60 seconds before scanning again.');
        }
        if (res.status === 413) {
          throw new Error(`Payload too large (${content.length.toLocaleString()} characters). Maximum 10,000 characters allowed.`);
        }
        throw new Error(data.error || 'Security audit request failed.');
      }

      setAuditResult(data.audit);
      saveToHistory(data.audit, content);
    } catch (err: any) {
      console.error('Audit Error:', err);
      setError(
        err.message || 'An unexpected error occurred while analyzing the security payload. Please try again.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 cyber-grid flex flex-col selection:bg-cyan-500/30">
      {/* Navigation */}
      <Navbar
        historyCount={history.length}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenOwaspMatrix={() => setIsOwaspModalOpen(true)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        hasAuditResult={!!auditResult}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 flex flex-col gap-6">
        {/* Hero Tagline / Security Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-sm sm:text-base font-bold text-slate-100 tracking-tight flex items-center gap-2 font-mono">
                AI CYBERSECURITY AUDITOR & CODE ANALYZER
              </h1>
              <p className="text-xs text-slate-400 font-sans">
                Real-time SAST vulnerability inspection for OWASP Top 10, XSS, SQLi, SSRF, & unsanitized payloads with automated patch generation.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto font-mono text-xs">
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-300">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>Full-Stack SAST Active</span>
            </span>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            type="button"
            onClick={() => setActiveView('module')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-mono font-bold transition-all ${
              activeView === 'module'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Security Analyzer Module</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveView('full')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-mono font-bold transition-all ${
              activeView === 'full'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-slate-500" />
            <span>Full SAST Suite (Logs & Presets)</span>
          </button>
        </div>

        {/* View 1: SecurityAnalyzerModule */}
        {activeView === 'module' ? (
          <SecurityAnalyzerModule />
        ) : (
          /* View 2: Full Workspace with Presets */
          <>
            {/* Preset Vectors Selector */}
            <PresetSelector
              selectedPresetId={selectedPresetId}
              onSelectPreset={handleSelectPreset}
            />

            {/* Error Banner if any */}
            {error && (
              <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs sm:text-sm flex items-start gap-3">
                <AlertCircle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
                <div className="flex-1">
                  <strong className="font-semibold block">Audit Engine Error:</strong>
                  <p className="mt-0.5 font-mono text-xs">{error}</p>
                </div>
                <button
                  onClick={() => setError(null)}
                  className="text-rose-400 hover:text-rose-200 text-xs font-mono font-bold"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* Workspace: Top Editor, Bottom/Right Report */}
            <div className="space-y-6">
              {/* Code Input Editor */}
              <CodeInputEditor
                inputType={inputType}
                setInputType={setInputType}
                targetEnvironment={targetEnvironment}
                setTargetEnvironment={setTargetEnvironment}
                content={content}
                setContent={(val) => {
                  setContent(val);
                  setSelectedPresetId(null);
                }}
                contextNotes={contextNotes}
                setContextNotes={setContextNotes}
                onAudit={runAudit}
                isLoading={isLoading}
              />

              {/* Audit Results View (or empty state prompt) */}
              {auditResult ? (
                <div id="audit-report-container">
                  <AuditReportView
                    audit={auditResult}
                    originalCode={content}
                    onOpenSimulator={() => setIsSimulatorOpen(true)}
                  />
                </div>
              ) : !isLoading ? (
                <div className="p-8 sm:p-12 text-center rounded-2xl bg-slate-900/40 border border-dashed border-slate-800 flex flex-col items-center justify-center">
                  <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-400 mb-3 shadow-inner">
                    <Search className="w-6 h-6 text-cyan-400" />
                  </div>
                  <h3 className="text-sm sm:text-base font-bold text-slate-200 font-mono">
                    Ready for Security Audit
                  </h3>
                  <p className="text-xs text-slate-400 max-w-md mt-1 mb-4 font-sans leading-relaxed">
                    Choose one of the sample presets above or paste your own code, raw HTTP payload, or server log to start deep vulnerability analysis.
                  </p>
                  <button
                    type="button"
                    onClick={runAudit}
                    className="px-5 py-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-xs font-bold transition-all shadow-sm"
                  >
                    Analyze Current Sample ({selectedPresetId ? 'SQL Injection' : 'Custom Input'})
                  </button>
                </div>
              ) : null}
            </div>
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0d131f]/80 py-4 mt-12 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-bold">SecuLens Security Suite</span>
            <span>•</span>
            <span>OWASP Top 10 • CWE • CVSS v3.1 Compliant</span>
          </div>
          <div>
            Powered by <span className="text-cyan-400 font-semibold">Gemini 3.8 Flash</span> (Server-Side Proxy)
          </div>
        </div>
      </footer>

      {/* Modals & Drawers */}
      {auditResult && (
        <ExploitSimulatorModal
          isOpen={isSimulatorOpen}
          onClose={() => setIsSimulatorOpen(false)}
          audit={auditResult}
        />
      )}

      <OwaspReferenceModal
        isOpen={isOwaspModalOpen}
        onClose={() => setIsOwaspModalOpen(false)}
      />

      <HistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={history}
        onSelectHistoryItem={handleSelectHistoryItem}
        onClearHistory={handleClearHistory}
      />
    </div>
  );
}
