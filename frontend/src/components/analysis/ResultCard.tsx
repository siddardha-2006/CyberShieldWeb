import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  AlertOctagon, 
  ChevronDown, 
  ChevronUp, 
  Lock, 
  Cpu, 
  Database, 
  Eye,
  CheckCircle2,
  RefreshCw,
  Search,
  HelpCircle,
  Shield,
  CreditCard,
  KeyRound,
  FileWarning,
  Languages
} from 'lucide-react';
import { AnalysisResponse, EngineResult } from '../../types';
import { HudBracket } from '../common/HudBracket';

interface ResultCardProps {
  result: AnalysisResponse;
  onNewAnalysis: () => void;
  onReportThreat: (target: string, cat: string) => void;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result, onNewAnalysis, onReportThreat }) => {
  const [showRawJson, setShowRawJson] = useState(false);
  const [expandedEngine, setExpandedEngine] = useState<string | null>('threat_intelligence');
  const { assessment, engines, explainability, indicator_hmac, duration_ms } = result;

  const severityConfig = {
    safe: {
      color: 'text-cyber-safe',
      border: 'border-cyber-safe/70',
      bg: 'bg-cyber-safe/10',
      badgeBg: 'bg-cyber-safe/25 text-cyber-safe border-cyber-safe/50',
      icon: ShieldCheck,
      title: 'SAFE / CLEAN CONTENT',
      description: 'No malicious threats, credential harvesting, or deceptive patterns found.',
    },
    suspicious: {
      color: 'text-cyber-warn',
      border: 'border-cyber-warn/70',
      bg: 'bg-cyber-warn/10',
      badgeBg: 'bg-cyber-warn/25 text-cyber-warn border-cyber-warn/50',
      icon: AlertTriangle,
      title: 'SUSPICIOUS / ELEVATED CAUTION',
      description: 'Unusual patterns or high urgency detected. Proceed with care.',
    },
    high_risk: {
      color: 'text-cyber-warn',
      border: 'border-cyber-warn/80',
      bg: 'bg-cyber-warn/15',
      badgeBg: 'bg-cyber-warn/30 text-cyber-warn border-cyber-warn/60',
      icon: ShieldAlert,
      title: 'HIGH RISK THREAT DETECTED',
      description: 'Strong indicators of credential theft or deceptive social engineering.',
    },
    critical: {
      color: 'text-cyber-danger',
      border: 'border-cyber-danger/80',
      bg: 'bg-cyber-danger/15',
      badgeBg: 'bg-cyber-danger/30 text-cyber-danger border-cyber-danger/60',
      icon: AlertOctagon,
      title: 'CRITICAL MALICIOUS THREAT',
      description: 'Confirmed dangerous phishing landing page or fraudulent solicitations.',
    },
  };

  const currentSev = severityConfig[assessment.severity] || severityConfig.safe;
  const SevIcon = currentSev.icon;

  const engineMeta = [
    { 
      key: 'rules', 
      label: 'Rule Engine', 
      icon: ShieldCheck, 
      weight: '25% weight',
      activeBorder: 'border-emerald-400 bg-emerald-950/60 shadow-[0_0_15px_rgba(52,211,153,0.3)]',
      baseBorder: 'border-emerald-500/30 hover:border-emerald-400/60 bg-pine-900/90',
      iconColor: 'text-emerald-400',
      titleColor: 'text-emerald-200',
      tagColor: 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
    },
    { 
      key: 'nlp', 
      label: 'AI / NLP Engine', 
      icon: Cpu, 
      weight: '30% weight',
      activeBorder: 'border-purple-400 bg-purple-950/60 shadow-[0_0_15px_rgba(168,85,247,0.3)]',
      baseBorder: 'border-purple-500/30 hover:border-purple-400/60 bg-pine-900/90',
      iconColor: 'text-purple-400',
      titleColor: 'text-purple-200',
      tagColor: 'bg-purple-950/80 text-purple-300 border-purple-500/40'
    },
    { 
      key: 'threat_intelligence', 
      label: 'Threat Intel', 
      icon: Database, 
      weight: '25% weight',
      activeBorder: 'border-amber-400 bg-amber-950/60 shadow-[0_0_15px_rgba(251,191,36,0.3)]',
      baseBorder: 'border-amber-500/30 hover:border-amber-400/60 bg-pine-900/90',
      iconColor: 'text-amber-400',
      titleColor: 'text-amber-200',
      tagColor: 'bg-amber-950/80 text-amber-300 border-amber-500/40'
    },
    { 
      key: 'behavior', 
      label: 'Behavior Sandbox', 
      icon: Eye, 
      weight: '20% weight',
      activeBorder: 'border-sky-400 bg-sky-950/60 shadow-[0_0_15px_rgba(56,189,248,0.3)]',
      baseBorder: 'border-sky-500/30 hover:border-sky-400/60 bg-pine-900/90',
      iconColor: 'text-sky-400',
      titleColor: 'text-sky-200',
      tagColor: 'bg-sky-950/80 text-sky-300 border-sky-500/40'
    },
  ];

  const threatIntel = engines.threat_intelligence;
  const threatSources = threatIntel?.sources || ['VirusTotal', 'URLhaus', 'PhishTank', 'CyberShield Feed'];
  const hasPhishTankHit = threatSources.includes('PhishTank') && (threatIntel?.score || 0) > 0;

  // Helper to parse "Title: Description" strings into structured objects
  const parseReason = (raw: string) => {
    const colonIdx = raw.indexOf(':');
    if (colonIdx > 0 && colonIdx < 50) {
      return {
        title: raw.substring(0, colonIdx).trim(),
        desc: raw.substring(colonIdx + 1).trim()
      };
    }
    return {
      title: 'Security Finding',
      desc: raw.trim()
    };
  };

  // Helper to select an appropriate icon for an explainability finding
  const getReasonIcon = (title: string) => {
    const t = title.toLowerCase();
    if (t.includes('phishtank') || t.includes('blacklist') || t.includes('threat')) {
      return <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0" />;
    }
    if (t.includes('financial') || t.includes('fee') || t.includes('payment') || t.includes('wire')) {
      return <CreditCard className="w-4 h-4 text-amber-400 flex-shrink-0" />;
    }
    if (t.includes('password') || t.includes('otp') || t.includes('credential') || t.includes('login') || t.includes('auth')) {
      return <KeyRound className="w-4 h-4 text-orange-400 flex-shrink-0" />;
    }
    if (t.includes('urgency') || t.includes('lure') || t.includes('prize') || t.includes('scam')) {
      return <AlertTriangle className="w-4 h-4 text-amber-300 flex-shrink-0" />;
    }
    if (t.includes('clean') || t.includes('safe') || t.includes('natural')) {
      return <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />;
    }
    return <FileWarning className="w-4 h-4 text-pine-300 flex-shrink-0" />;
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* 2 EQUAL COLUMNS ANALYSIS LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8 items-start">
        
        {/* ========================================================================= */}
        {/* LEFT COLUMN: Verdict, Risk Score, Explainability & Recommended Steps      */}
        {/* ========================================================================= */}
        <div className="space-y-5 flex flex-col justify-start">
          
          {/* Regional Multilingual Translation Telemetry Banner */}
          {result.language_info?.is_translated && (
            <div className="p-4 rounded-2xl bg-indigo-950/50 border border-indigo-500/40 text-indigo-100 flex items-start space-x-3.5 shadow-xl animate-fadeIn">
              <div className="p-2 rounded-xl bg-indigo-900/80 border border-indigo-500/40 text-indigo-300 mt-0.5">
                <Languages className="w-5 h-5 text-indigo-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-indigo-200 uppercase tracking-wider">
                    Auto-Detected Language: {result.language_info.detected_language}
                  </span>
                  <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-indigo-900 text-indigo-300 font-bold border border-indigo-500/40 font-mono">
                    Auto-Translated
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded-xl bg-pine-950/80 border border-indigo-900/60">
                    <div className="text-[10px] font-bold text-indigo-300 uppercase tracking-wider mb-1">
                      Original ({result.language_info.detected_language}):
                    </div>
                    <div className="text-pine-200/90 italic font-sans">{result.language_info.original_text}</div>
                  </div>
                  <div className="p-2.5 rounded-xl bg-pine-950/80 border border-indigo-900/60">
                    <div className="text-[10px] font-bold text-emerald-300 uppercase tracking-wider mb-1">
                      English Translation Analyzed:
                    </div>
                    <div className="text-pine-100 font-sans">{result.language_info.translated_text}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* PhishTank Priority Spotlight Banner */}
          {hasPhishTankHit && (
            <div className="p-4 rounded-2xl bg-red-950/60 border border-red-500/60 text-red-100 flex items-start space-x-3.5 shadow-xl animate-fadeIn">
              <div className="p-2 rounded-xl bg-red-900/80 border border-red-500/40 text-red-300 mt-0.5">
                <AlertOctagon className="w-5 h-5 text-red-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-red-200 uppercase tracking-wider">
                    Confirmed Threat in PhishTank Database
                  </span>
                  <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-red-900 text-red-300 font-bold border border-red-500/40 font-mono">
                    Blacklist Match
                  </span>
                </div>
                <p className="text-[11px] text-red-200/90 mt-1 leading-relaxed">
                  This destination is an active confirmed entry in global phishing intelligence feeds (PhishTank & Threat Feeds). Immediate reporting and containment is recommended.
                </p>
              </div>
            </div>
          )}

          {/* 1. Main High-Impact Verdict Card */}
          <HudBracket className={`border ${currentSev.border} ${currentSev.bg} shadow-glow-mint`}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-pine-600">
              
              {/* Left: Severity & Category */}
              <div className="flex items-start space-x-3.5">
                <div className={`p-3 rounded-2xl bg-pine-900 border ${currentSev.border} shadow-md mt-0.5`}>
                  <SevIcon className={`w-7 h-7 ${currentSev.color}`} />
                </div>
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <span className={`px-2.5 py-0.5 rounded-full text-[11px] uppercase font-bold tracking-wider border ${currentSev.badgeBg}`}>
                      {currentSev.title}
                    </span>
                    <span className="text-[11px] text-pine-300 font-medium font-mono">
                      {Math.round(assessment.confidence * 100)}% Conf
                    </span>
                  </div>
                  <h2 className="text-xl sm:text-2xl font-bold text-pine-100 mt-0.5">
                    {assessment.category}
                  </h2>
                </div>
              </div>

              {/* Right: Large Risk Score */}
              <div className="flex items-center space-x-3 self-end sm:self-center bg-pine-900/95 px-5 py-3 rounded-xl border border-pine-600 shadow-inner">
                <div className="text-right">
                  <div className="text-[10px] text-pine-300 uppercase tracking-widest font-bold">RISK</div>
                  <div className="text-[11px] text-pine-100/60">/ 100</div>
                </div>
                <div className={`text-3xl sm:text-4xl font-black font-mono tracking-tight ${currentSev.color}`}>
                  {assessment.risk_score}
                </div>
              </div>
            </div>

            {/* Description & Action Directive Callout */}
            <div className="mt-4 space-y-3">
              <p className="text-xs sm:text-sm text-pine-200 leading-relaxed font-sans">
                {currentSev.description}
              </p>

              <div className="pt-2 border-t border-pine-600/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5">
                <div className="flex items-center space-x-2">
                  <span className="text-[11px] text-pine-300 uppercase font-bold tracking-wider">
                    DIRECTIVE:
                  </span>
                  <span className={`text-[11px] px-2.5 py-0.5 rounded-lg font-bold uppercase tracking-wider ${
                    assessment.recommended_action === 'ALLOW' ? 'bg-cyber-safe/25 text-cyber-safe border border-cyber-safe/50' :
                    assessment.recommended_action === 'WARN' ? 'bg-cyber-warn/25 text-cyber-warn border border-cyber-warn/50' :
                    assessment.recommended_action === 'DO_NOT_INTERACT' ? 'bg-cyber-warn/35 text-cyber-warn border border-cyber-warn/60' :
                    'bg-cyber-danger/35 text-cyber-danger border border-cyber-danger/60'
                  }`}>
                    {assessment.recommended_action.replace(/_/g, ' ')}
                  </span>
                </div>
                <p className="text-xs text-pine-100/90 font-medium">
                  {assessment.action_details}
                </p>
              </div>
            </div>
          </HudBracket>

          {/* 2. Detected Evidence & Explainability Box (Refactored for Superior Readability) */}
          <HudBracket>
            <div className="space-y-4">
              
              {/* Section Header with Icon */}
              <div className="flex items-center justify-between pb-2 border-b border-pine-600/60">
                <div className="flex items-center space-x-2">
                  <HelpCircle className="w-4 h-4 text-pine-300" />
                  <h3 className="text-xs font-bold text-pine-200 uppercase tracking-wider">
                    Why Was This Flagged? (Clear Breakdown)
                  </h3>
                </div>
                <span className="text-[10px] text-pine-300/70 font-mono">
                  {explainability.key_reasons.length} Core Factors
                </span>
              </div>

              {/* Executive Summary Card */}
              <div className={`p-3.5 rounded-xl border text-xs sm:text-sm leading-relaxed ${
                assessment.severity === 'safe' 
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-100' 
                  : 'bg-pine-900/90 border-pine-600 text-pine-100'
              }`}>
                <div className="font-semibold text-pine-100 mb-1 flex items-center space-x-1.5">
                  <Shield className="w-3.5 h-3.5 text-pine-300" />
                  <span className="text-[11px] uppercase tracking-wider text-pine-300 font-bold">Executive Assessment:</span>
                </div>
                <p className="text-pine-100/95 font-sans leading-relaxed">
                  {explainability.summary}
                </p>
              </div>

              {/* Structured Key Reasons Cards */}
              <div className="space-y-2.5 pt-1">
                <div className="text-[11px] font-bold text-pine-300 uppercase tracking-wider">
                  Detailed Finding Points:
                </div>

                {explainability.key_reasons.map((rawReason, idx) => {
                  const parsed = parseReason(rawReason);
                  const isCritical = assessment.severity === 'critical';
                  const isSafe = assessment.severity === 'safe';

                  return (
                    <div
                      key={idx}
                      className={`p-3 rounded-xl border bg-pine-950/80 transition-all flex items-start space-x-3 shadow-sm ${
                        isCritical
                          ? 'border-l-4 border-l-red-500 border-pine-700/80 hover:border-pine-500'
                          : isSafe
                          ? 'border-l-4 border-l-emerald-400 border-pine-700/80 hover:border-pine-500'
                          : 'border-l-4 border-l-amber-400 border-pine-700/80 hover:border-pine-500'
                      }`}
                    >
                      <div className="mt-0.5">
                        {getReasonIcon(parsed.title)}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-bold text-pine-100 tracking-tight flex items-center justify-between">
                          <span>{parsed.title}</span>
                          <span className="text-[10px] text-pine-400 font-mono">#{idx + 1}</span>
                        </div>
                        <p className="text-[11px] text-pine-200/90 leading-relaxed mt-1 font-sans">
                          {parsed.desc}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Recommended Safety Steps (Visual Checklist) */}
              <div className="pt-3 border-t border-pine-600/60 space-y-2">
                <h4 className="text-xs font-bold text-pine-300 uppercase tracking-wider flex items-center space-x-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-pine-300" />
                  <span>Recommended Action Checklist</span>
                </h4>
                
                <div className="grid grid-cols-1 gap-2">
                  {explainability.safe_steps.map((step, idx) => (
                    <div
                      key={idx}
                      className="flex items-start space-x-3 p-2.5 rounded-xl bg-pine-900/80 border border-pine-600/80 text-xs text-pine-100/95 shadow-sm"
                    >
                      <span className="flex-shrink-0 w-4 h-4 rounded-full bg-pine-800 border border-pine-500 text-[10px] font-mono font-bold flex items-center justify-center text-pine-200 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="leading-snug">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </HudBracket>

          {/* Action Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-2xl bg-pine-900/95 border border-pine-600 text-xs">
            <div className="flex items-center space-x-2 text-pine-300/70 truncate max-w-xs font-mono text-[11px]">
              <Lock className="w-3.5 h-3.5 text-pine-300 flex-shrink-0" />
              <span className="truncate">HMAC: {indicator_hmac}</span>
            </div>

            <div className="flex items-center space-x-2.5 w-full sm:w-auto justify-end">
              <button
                onClick={() => onReportThreat(indicator_hmac, assessment.category)}
                className="px-3.5 py-2 rounded-xl pine-btn-secondary text-xs font-semibold"
              >
                Report
              </button>
              <button
                onClick={onNewAnalysis}
                className="px-5 py-2 rounded-xl pine-btn-primary font-bold text-xs flex items-center space-x-1.5 shadow-glow-mint"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Scan Another Item</span>
              </button>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* RIGHT COLUMN: 4 Parallel Engines Breakdown & Deep Telemetry Inspector    */}
        {/* ========================================================================= */}
        <div className="space-y-5 flex flex-col justify-start">
          
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase tracking-wider font-bold text-pine-300">
                Parallel Engines Breakdown
              </span>
              <span className="text-xs text-pine-300/70 font-mono">
                Analyzed in {duration_ms}ms
              </span>
            </div>

            {/* 4 Engine Cards with Unique Sector Colors */}
            <div className="grid grid-cols-2 gap-3">
              {engineMeta.map((meta) => {
                const engResult = (engines as any)[meta.key] as EngineResult | undefined;
                const Icon = meta.icon;
                const score = engResult ? engResult.score : 0;
                const status = engResult ? engResult.status : 'unavailable';
                const latency = engResult ? engResult.latency_ms : 0;
                const isSelected = expandedEngine === meta.key;

                let scoreColor = 'text-cyber-safe';
                if (score >= 80) scoreColor = 'text-cyber-danger';
                else if (score >= 50) scoreColor = 'text-cyber-warn';
                else if (score >= 25) scoreColor = 'text-pine-300';

                return (
                  <div
                    key={meta.key}
                    onClick={() => setExpandedEngine(isSelected ? null : meta.key)}
                    className={`p-3.5 rounded-2xl border cursor-pointer transition-all shadow-sm flex flex-col justify-between ${
                      isSelected ? meta.activeBorder : meta.baseBorder
                    }`}
                  >
                    <div className="flex items-center justify-between pb-2 border-b border-pine-600/60">
                      <div className="flex items-center space-x-1.5 truncate">
                        <Icon className={`w-3.5 h-3.5 ${meta.iconColor} flex-shrink-0`} />
                        <span className={`text-xs font-bold ${meta.titleColor} truncate`}>{meta.label}</span>
                      </div>
                      <span className="text-[10px] text-pine-300/60 font-mono">{meta.weight}</span>
                    </div>

                    <div className="my-2.5 flex items-baseline justify-between">
                      <span className={`text-xl sm:text-2xl font-mono font-bold ${scoreColor}`}>
                        {status === 'not_applicable' ? 'N/A' : `${score}/100`}
                      </span>
                      <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded font-semibold border ${
                        score >= 80 ? 'bg-red-950/60 text-red-300 border-red-500/40' :
                        score >= 50 ? 'bg-amber-950/60 text-amber-300 border-amber-500/40' :
                        meta.tagColor
                      }`}>
                        {meta.key === 'threat_intelligence' ? (score > 0 ? 'Threat Listed' : 'Clean') : status}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-pine-300/70 pt-1.5 border-t border-pine-600/40 font-mono">
                      <span>{engResult?.evidence?.length || 0} findings</span>
                      <span>{latency}ms</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Active Engine Details Inspector */}
          {expandedEngine && (
            <div className="p-4 rounded-2xl bg-pine-900/90 border border-pine-600 space-y-3 animate-fadeIn">
              <div className="flex items-center justify-between pb-2.5 border-b border-pine-600">
                <div className="flex items-center space-x-2 text-xs sm:text-sm font-bold text-pine-100">
                  <Search className="w-4 h-4 text-pine-300" />
                  <span>
                    {expandedEngine === 'threat_intelligence' && <span className="text-amber-300">Threat Intelligence Feeds & Blacklist Telemetry</span>}
                    {expandedEngine === 'rules' && <span className="text-emerald-300">Deterministic Rule Engine Matches</span>}
                    {expandedEngine === 'nlp' && <span className="text-purple-300">AI & NLP Linguistic Classification Signals</span>}
                    {expandedEngine === 'behavior' && <span className="text-sky-300">Behavioral DOM & Sandbox Emulation Findings</span>}
                  </span>
                </div>
                <button 
                  onClick={() => setExpandedEngine(null)} 
                  className="text-xs text-pine-300 hover:text-white"
                >
                  Close
                </button>
              </div>

              {/* If Threat Intelligence is expanded */}
              {expandedEngine === 'threat_intelligence' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2.5">
                    {[
                      { name: 'VirusTotal', desc: '88 Antivirus Vendors', hit: threatSources.includes('VirusTotal') && (threatIntel?.score || 0) > 0, theme: 'border-blue-500/40' },
                      { name: 'URLhaus', desc: 'abuse.ch Malware Feed', hit: threatSources.includes('URLhaus') && (threatIntel?.score || 0) > 0, theme: 'border-orange-500/40' },
                      { name: 'PhishTank', desc: 'Verified Phishing Community', hit: threatSources.includes('PhishTank') && (threatIntel?.score || 0) > 0, theme: 'border-red-500/40' },
                      { name: 'CyberShield Feed', desc: '223k+ Malicious Index', hit: threatSources.includes('CyberShield Threat Feed') && (threatIntel?.score || 0) > 0, theme: 'border-emerald-500/40' },
                    ].map((p, idx) => (
                      <div key={idx} className={`p-2.5 rounded-xl bg-pine-950/80 border ${p.theme} flex flex-col justify-between shadow-sm`}>
                        <div>
                          <div className="text-xs font-bold text-pine-100">{p.name}</div>
                          <div className="text-[10px] text-pine-300/60">{p.desc}</div>
                        </div>
                        <div className="mt-2 pt-1.5 border-t border-pine-700/50">
                          {p.hit ? (
                            <span className="text-[9px] font-bold text-red-400 uppercase bg-red-950/50 px-1.5 py-0.5 rounded border border-red-800/60">
                              Blacklisted Threat Hit
                            </span>
                          ) : (
                            <span className="text-[9px] font-bold text-emerald-400 uppercase bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-800/60">
                              0 Blacklist Hits (Clean)
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {threatIntel?.evidence && threatIntel.evidence.length > 0 ? (
                    <div className="space-y-2 pt-1">
                      <div className="text-[11px] font-bold text-amber-300 uppercase tracking-wider">Matched Threat Records:</div>
                      {threatIntel.evidence.map((ev, idx) => (
                        <div key={idx} className="p-2.5 rounded-xl bg-red-950/30 border border-red-500/30 text-xs text-pine-100 flex items-start space-x-2">
                          <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                          <div>
                            <div className="font-bold text-red-300 text-xs">{ev.title}</div>
                            <div className="text-pine-200/90 text-[11px] mt-0.5">{ev.description}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-200 flex items-center space-x-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                      <span>Destination checked across 88 global antivirus vendors and 4 threat databases — no threat hits or blacklisting found.</span>
                    </div>
                  )}
                </div>
              )}

              {/* If Rules is expanded */}
              {expandedEngine === 'rules' && (
                <div className="space-y-2">
                  {(engines.rules?.evidence || []).length > 0 ? (
                    engines.rules?.evidence.map((ev, idx) => (
                      <div key={idx} className="p-2.5 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-xs text-pine-100">
                        <div className="font-bold text-emerald-300 text-xs">{ev.title}</div>
                        <div className="text-emerald-100/90 text-[11px] mt-0.5">{ev.description}</div>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-emerald-300/80">No malicious rule triggers detected (Domain is clean or allowlisted).</div>
                  )}
                </div>
              )}

              {/* If NLP is expanded */}
              {expandedEngine === 'nlp' && (
                <div className="space-y-2">
                  <div className="text-xs text-purple-200">
                    ML Phishing Classifier Score: <span className="font-mono font-bold text-purple-100">{engines.nlp?.score}/100</span>
                  </div>
                  {(engines.nlp?.evidence || []).map((ev, idx) => (
                    <div key={idx} className="p-2.5 rounded-xl bg-purple-950/30 border border-purple-500/40 text-xs text-pine-100">
                      <div className="font-bold text-purple-300 text-xs">{ev.title}</div>
                      <div className="text-purple-100/90 text-[11px] mt-0.5">{ev.description}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* If Behavior is expanded */}
              {expandedEngine === 'behavior' && (
                <div className="space-y-2">
                  {(engines.behavior?.evidence || []).length > 0 ? (
                    engines.behavior?.evidence.map((ev, idx) => (
                      <div key={idx} className="p-2.5 rounded-xl bg-sky-950/30 border border-sky-500/40 text-xs text-pine-100">
                        <div className="font-bold text-sky-300 text-xs">{ev.title}</div>
                        <div className="text-sky-100/90 text-[11px] mt-0.5">{ev.description}</div>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-sky-300/80">No dangerous payload behaviors or form hijacking detected.</div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Technical raw JSON toggle */}
          <div className="pt-1">
            <button
              onClick={() => setShowRawJson(!showRawJson)}
              className="text-xs text-pine-300/70 hover:text-pine-100 flex items-center space-x-1.5 font-medium"
            >
              {showRawJson ? <ChevronUp className="w-3.5 h-3.5 text-pine-300" /> : <ChevronDown className="w-3.5 h-3.5 text-pine-300" />}
              <span>{showRawJson ? 'Hide Raw Technical JSON' : 'Show Raw Technical Telemetry (Developers / SOC)'}</span>
            </button>

            {showRawJson && (
              <pre className="mt-2.5 p-3.5 rounded-xl bg-pine-950 border border-pine-600 text-[11px] font-mono text-pine-100/80 overflow-x-auto max-h-72 shadow-inner">
                {JSON.stringify(result, null, 2)}
              </pre>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
