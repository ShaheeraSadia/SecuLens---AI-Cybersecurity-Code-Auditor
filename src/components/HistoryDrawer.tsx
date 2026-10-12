import React from 'react';
import { X, History, Trash2, ArrowUpRight, ShieldCheck, ShieldAlert } from 'lucide-react';
import { AuditHistoryItem } from '../types/security';
import { VulnerabilityBadge } from './VulnerabilityBadge';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  history: AuditHistoryItem[];
  onSelectHistoryItem: (item: AuditHistoryItem) => void;
  onClearHistory: () => void;
}

export const HistoryDrawer: React.FC<Props> = ({
  isOpen,
  onClose,
  history,
  onSelectHistoryItem,
  onClearHistory,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-md bg-[#0f172a] border-l border-slate-800 h-full flex flex-col shadow-2xl">
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 font-mono">
              Audit Scan History ({history.length})
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {history.length === 0 ? (
            <div className="text-center py-12 text-slate-500 font-mono text-xs">
              No audit scans recorded yet.
              <p className="text-[11px] text-slate-600 mt-1">
                Audits will automatically be saved to local session history.
              </p>
            </div>
          ) : (
            history.map((item) => (
              <div
                key={item.id}
                onClick={() => {
                  onSelectHistoryItem(item);
                  onClose();
                }}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition-all cursor-pointer group flex flex-col gap-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <VulnerabilityBadge riskLevel={item.result.riskLevel} size="sm" />
                  <span className="text-[10px] font-mono text-slate-500">
                    {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>

                <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors line-clamp-1">
                  {item.title}
                </div>

                <div className="p-2 rounded bg-[#090d16] font-mono text-[11px] text-slate-400 line-clamp-2">
                  {item.snippetPreview}
                </div>

                <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-900">
                  <span>CVSS: {item.result.cvssScore.toFixed(1)}</span>
                  <span className="flex items-center gap-1 text-cyan-400 group-hover:underline">
                    Load Scan <ArrowUpRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Drawer Footer */}
        {history.length > 0 && (
          <div className="p-4 border-t border-slate-800 bg-slate-900/40 flex justify-between items-center">
            <button
              onClick={onClearHistory}
              className="text-xs font-mono text-rose-400 hover:text-rose-300 flex items-center gap-1.5 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </button>
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
