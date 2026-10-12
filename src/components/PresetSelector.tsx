import React from 'react';
import { PRESET_SAMPLES } from '../data/presets';
import { PresetSample } from '../types/security';
import { Sparkles, Code2, Globe, FileText, CheckCircle2 } from 'lucide-react';

interface Props {
  selectedPresetId: string | null;
  onSelectPreset: (preset: PresetSample) => void;
}

export const PresetSelector: React.FC<Props> = ({
  selectedPresetId,
  onSelectPreset,
}) => {
  const getIcon = (type: PresetSample['inputType']) => {
    switch (type) {
      case 'code':
        return <Code2 className="w-3.5 h-3.5 text-cyan-400" />;
      case 'http':
        return <Globe className="w-3.5 h-3.5 text-amber-400" />;
      case 'log':
        return <FileText className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 font-mono">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>Quick Attack Vector & Baseline Presets:</span>
        </label>
        <span className="text-[11px] text-slate-500 font-mono">Click to populate & audit</span>
      </div>

      <div className="flex flex-wrap gap-2">
        {PRESET_SAMPLES.map((preset) => {
          const isSelected = selectedPresetId === preset.id;
          const isSafe = preset.id === 'safe-code-baseline';

          return (
            <button
              key={preset.id}
              onClick={() => onSelectPreset(preset)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all border text-left ${
                isSelected
                  ? isSafe
                    ? 'bg-emerald-950/80 border-emerald-500 text-emerald-200 ring-1 ring-emerald-500'
                    : 'bg-cyan-950/80 border-cyan-500 text-cyan-200 ring-1 ring-cyan-500'
                  : isSafe
                  ? 'bg-slate-900/60 border-emerald-700/40 text-emerald-400 hover:bg-slate-800 hover:border-emerald-500/70'
                  : 'bg-slate-900/60 border-slate-700/60 text-slate-300 hover:bg-slate-800 hover:border-slate-500'
              }`}
              title={preset.description}
            >
              {isSafe ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : getIcon(preset.inputType)}
              <span className="font-medium truncate max-w-[170px] sm:max-w-none">{preset.badge}</span>
              <span className="text-[10px] opacity-60 hidden md:inline">({preset.title.split(' ')[0]})</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
