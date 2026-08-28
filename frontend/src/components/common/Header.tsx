import React from 'react';
import { Shield, History, AlertOctagon } from 'lucide-react';

interface HeaderProps {
  onOpenHistory: () => void;
  onOpenReport: () => void;
  onNewScan: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenHistory, onOpenReport, onNewScan }) => {
  return (
    <header className="w-full border-b border-pine-600/40 bg-pine-900/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand Logo & Name */}
        <div 
          onClick={onNewScan} 
          className="flex items-center space-x-3 cursor-pointer group"
        >
          <div className="w-9 h-9 rounded-lg bg-pine-700 border border-pine-300/40 flex items-center justify-center shadow-glow-mint group-hover:border-pine-300 transition-all">
            <Shield className="w-5 h-5 text-pine-100" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-base font-bold tracking-wider text-pine-100 uppercase">
                Cyber<span className="text-pine-300">Shield</span>
              </span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase bg-pine-600/40 text-pine-300 rounded border border-pine-600">
                Live
              </span>
            </div>
            <p className="text-[11px] text-pine-300/70 hidden sm:block">
              Explainable Threat Detection
            </p>
          </div>
        </div>

        {/* 4 Engine Pill Indicator */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1 rounded-full bg-pine-800 border border-pine-600/60 text-xs text-pine-100/90">
          <span className="w-2 h-2 rounded-full bg-pine-300 animate-pulse" />
          <span className="font-medium text-pine-300">4 Detection Engines:</span>
          <span className="text-pine-100/70">Rules • AI/NLP • Threat Intel • Sandbox</span>
        </div>

        {/* Actions */}
        <div className="flex items-center space-x-2.5">
          <button
            onClick={onOpenHistory}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-md text-xs font-mono text-pine-100 bg-pine-800 hover:bg-pine-700 border border-pine-600 hover:border-pine-300 transition-all"
          >
            <History className="w-3.5 h-3.5 text-pine-300" />
            <span>History</span>
          </button>

          <button
            onClick={onOpenReport}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-md text-xs font-mono text-pine-100 bg-pine-600 hover:bg-pine-600/80 border border-pine-300/60 hover:border-pine-300 transition-all shadow-glow-mint"
          >
            <AlertOctagon className="w-3.5 h-3.5 text-pine-300" />
            <span>Report Threat</span>
          </button>
        </div>
      </div>
    </header>
  );
};
