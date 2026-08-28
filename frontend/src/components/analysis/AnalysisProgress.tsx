import React, { useEffect, useState } from 'react';
import { Cpu, ShieldCheck, Database, Eye, CheckCircle2, Loader2 } from 'lucide-react';
import { HudBracket } from '../common/HudBracket';

interface AnalysisProgressProps {
  input_type: string;
}

export const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ input_type }) => {
  const [stages, setStages] = useState({
    extraction: false,
    normalization: false,
    rules: false,
    nlp: false,
    intel: false,
    behavior: false,
  });

  useEffect(() => {
    const t1 = setTimeout(() => setStages((s) => ({ ...s, extraction: true })), 150);
    const t2 = setTimeout(() => setStages((s) => ({ ...s, normalization: true })), 350);
    const t3 = setTimeout(() => setStages((s) => ({ ...s, rules: true })), 600);
    const t4 = setTimeout(() => setStages((s) => ({ ...s, nlp: true })), 850);
    const t5 = setTimeout(() => setStages((s) => ({ ...s, intel: true })), 1100);
    const t6 = setTimeout(() => setStages((s) => ({ ...s, behavior: true })), 1400);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      clearTimeout(t5);
      clearTimeout(t6);
    };
  }, []);

  const engines = [
    { key: 'rules', label: 'Rule Engine', sub: 'Deterministic syntax & regex inspection', icon: ShieldCheck, done: stages.rules },
    { key: 'nlp', label: 'AI/NLP Intent Engine', sub: 'Semantic phishing & manipulation intent', icon: Cpu, done: stages.nlp },
    { key: 'intel', label: 'Threat Intel Engine', sub: 'VirusTotal, URLhaus & PhishTank feeds', icon: Database, done: stages.intel },
    { key: 'behavior', label: 'Behavioral Sandbox', sub: 'DOM forms & multi-hop redirect audit', icon: Eye, done: stages.behavior },
  ];

  return (
    <HudBracket className="w-full my-6 bg-cyber-dark/80">
      <div className="flex items-center justify-between pb-3 border-b border-cyber-cardborder mb-4">
        <div className="flex items-center space-x-2">
          <Loader2 className="w-4 h-4 text-cyber-sand animate-spin" />
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-cyber-sand font-semibold">
            PARALLEL TELEMETRY ENGAGED...
          </span>
        </div>
        <span className="text-[10px] font-mono text-cyber-ice/50 tracking-widest">
          VECTOR: {input_type.toUpperCase()}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
        {engines.map((eng) => {
          const Icon = eng.icon;
          return (
            <div
              key={eng.key}
              className={`p-3.5 rounded border transition-all duration-300 flex items-center justify-between ${
                eng.done
                  ? 'bg-cyber-card/90 border-cyber-sand/60 text-cyber-ice shadow-sm'
                  : 'bg-cyber-dark/80 border-cyber-cardborder text-cyber-ice/40'
              }`}
            >
              <div className="flex items-center space-x-3">
                <div className={`p-2 rounded ${eng.done ? 'bg-cyber-teal/60 text-cyber-ice' : 'bg-cyber-dark text-cyber-ice/30'}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-semibold text-xs text-cyber-ice tracking-wider">{eng.label}</div>
                  <div className="text-[10px] text-cyber-ice/60">{eng.sub}</div>
                </div>
              </div>

              <div>
                {eng.done ? (
                  <CheckCircle2 className="w-4 h-4 text-cyber-safe animate-pulse" />
                ) : (
                  <Loader2 className="w-3.5 h-3.5 text-cyber-sand animate-spin" />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </HudBracket>
  );
};
