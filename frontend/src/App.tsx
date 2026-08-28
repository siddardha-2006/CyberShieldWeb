import React, { useState, useRef } from 'react';
import { Header } from './components/common/Header';
import { CyberOrb } from './components/hero/CyberOrb';
import { HudBracket } from './components/common/HudBracket';
import { InputSelector } from './components/analysis/InputSelector';
import { UrlAnalyzer } from './components/analysis/UrlAnalyzer';
import { MessageAnalyzer } from './components/analysis/MessageAnalyzer';
import { EmailAnalyzer } from './components/analysis/EmailAnalyzer';
import { QrUploader } from './components/analysis/QrUploader';
import { WebpageAnalyzer } from './components/analysis/WebpageAnalyzer';
import { SocialAnalyzer } from './components/analysis/SocialAnalyzer';
import { AnalysisProgress } from './components/analysis/AnalysisProgress';
import { ResultCard } from './components/analysis/ResultCard';
import { HistoryModal } from './components/history/HistoryModal';
import { ReportModal } from './components/reports/ReportModal';
import { VantaBackground } from './components/common/VantaBackground';
import { InputType, AnalysisResponse, Severity } from './types';
import { apiService } from './services/api';
import { Sparkles, ShieldCheck, Cpu, Database, Eye } from 'lucide-react';

export const App: React.FC = () => {
  const [currentType, setCurrentType] = useState<InputType>('url');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportInitialTarget, setReportInitialTarget] = useState('');
  const [reportInitialCategory, setReportInitialCategory] = useState('phishing');
  const [error, setError] = useState<string | null>(null);

  const analyzerRef = useRef<HTMLDivElement | null>(null);

  const scrollToAnalyzer = () => {
    analyzerRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Trigger analysis for URL
  const handleAnalyzeUrl = async (url: string) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeUrl(url);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Analysis failed. Please verify the backend server is running.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger analysis for Message
  const handleAnalyzeMessage = async (text: string, sender?: string) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeMessage(text, sender);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Message analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger analysis for Email
  const handleAnalyzeEmail = async (data: any) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeEmail(data);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Email analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger analysis for QR
  const handleAnalyzeQr = async (data: any) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeQr(data);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'QR analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger analysis for Webpage
  const handleAnalyzeWebpage = async (url: string, html?: string) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeWebpage(url, html);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Webpage analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger analysis for Social
  const handleAnalyzeSocial = async (text: string, platform?: string) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await apiService.analyzeSocial(text, platform);
      setResult(res);
      scrollToAnalyzer();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Social message analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };


  const handleOpenReportFromCard = (target: string, cat: string) => {
    setReportInitialTarget(target);
    setReportInitialCategory(cat.toLowerCase().includes('phish') ? 'phishing' : 'malware');
    setReportOpen(true);
  };

  const currentSeverity: Severity = result ? result.assessment.severity : 'safe';

  return (
    <div className="relative min-h-screen flex flex-col bg-[#051F20] text-pine-100 selection:bg-pine-300 selection:text-pine-900">
      
      {/* 3D Animated Vanta.NET Background */}
      <VantaBackground />

      {/* Navigation Header */}
      <div className="relative z-10">
        <Header
          onOpenHistory={() => setHistoryOpen(true)}
          onOpenReport={() => {
            setReportInitialTarget('');
            setReportOpen(true);
          }}
          onNewScan={() => setResult(null)}
        />
      </div>

      {/* Main Container */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-10">
        
        {result ? (
          /* When Results are available, show full ResultCard */
          <div ref={analyzerRef} className="space-y-6">
            <ResultCard
              result={result}
              onNewAnalysis={() => setResult(null)}
              onReportThreat={handleOpenReportFromCard}
            />
          </div>
        ) : (
          /* ========================================================================= */
          /* 2 EQUAL COLUMN PARTS HOME PAGE LAYOUT                                     */
          /* ========================================================================= */
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-10 items-start">
            
            {/* ----------------------------------------------------------------------- */}
            {/* LEFT COLUMN: Hero Orb, Headline & Multi-Engine Defense Overview         */}
            {/* ----------------------------------------------------------------------- */}
            <div className="space-y-6 flex flex-col justify-center">
              
              {/* Cyber Orb Centerpiece */}
              <div className="flex justify-center -my-2">
                <CyberOrb
                  severity={currentSeverity}
                  isAnalyzing={loading}
                  score={undefined}
                />
              </div>

              {/* Title & Description */}
              <div className="space-y-3 text-center lg:text-left">
                <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-pine-800 border border-pine-600 text-xs font-semibold text-pine-300 shadow-sm">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Multi-Engine Zero-Trust Defense</span>
                </div>

                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-white leading-tight">
                  Instant Threat Detection & Analysis
                </h1>

                <p className="text-sm sm:text-base text-pine-300/90 leading-relaxed font-sans">
                  Verify any link, SMS, email, or QR code in seconds. Powered by 4 parallel neural and deterministic engines.
                </p>
              </div>

              {/* 4 Parallel Defense Engines Feature Badges */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 hover:border-emerald-400/80 transition-all flex items-start space-x-3 shadow-sm group">
                  <div className="p-2 rounded-lg bg-emerald-900/60 border border-emerald-500/40 text-emerald-400 group-hover:scale-105 transition-transform">
                    <ShieldCheck className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-emerald-200">Rule Engine</div>
                    <div className="text-[11px] text-emerald-300/70">40+ deterministic heuristic rules & brand correlation</div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-purple-950/40 border border-purple-500/40 hover:border-purple-400/80 transition-all flex items-start space-x-3 shadow-sm group">
                  <div className="p-2 rounded-lg bg-purple-900/60 border border-purple-500/40 text-purple-400 group-hover:scale-105 transition-transform">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-purple-200">AI / NLP Engine</div>
                    <div className="text-[11px] text-purple-300/70">Machine learning n-gram model trained on 450k+ samples</div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-500/40 hover:border-amber-400/80 transition-all flex items-start space-x-3 shadow-sm group">
                  <div className="p-2 rounded-lg bg-amber-900/60 border border-amber-500/40 text-amber-400 group-hover:scale-105 transition-transform">
                    <Database className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-amber-200">Threat Intel</div>
                    <div className="text-[11px] text-amber-300/70">Live VirusTotal, PhishTank & 223k+ local threat records</div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-sky-950/40 border border-sky-500/40 hover:border-sky-400/80 transition-all flex items-start space-x-3 shadow-sm group">
                  <div className="p-2 rounded-lg bg-sky-900/60 border border-sky-500/40 text-sky-400 group-hover:scale-105 transition-transform">
                    <Eye className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-sky-200">Behavior Sandbox</div>
                    <div className="text-[11px] text-sky-300/70">Interactive DOM inspection & redirect chain tracing</div>
                  </div>
                </div>
              </div>
            </div>

            {/* ----------------------------------------------------------------------- */}
            {/* RIGHT COLUMN: The Inspection Terminal & Active Analyzer Forms          */}
            {/* ----------------------------------------------------------------------- */}
            <div ref={analyzerRef} className="space-y-6">
              <HudBracket className="pine-card-hover shadow-2xl">
                
                {/* Clean Section Header */}
                <div className="text-center mb-5">
                  <h2 className="text-lg sm:text-xl font-bold text-pine-100">
                    What would you like to inspect?
                  </h2>
                  <p className="text-xs sm:text-sm text-pine-300/80 mt-0.5">
                    Select the content format below and click scan
                  </p>
                </div>

                {/* Error Banner if any */}
                {error && (
                  <div className="mb-5 p-3.5 rounded-xl bg-red-950/40 border border-red-500/30 text-red-200 text-xs flex items-center justify-between">
                    <span>{error}</span>
                    <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200 ml-3 font-bold">Dismiss</button>
                  </div>
                )}

                {/* Category Selector Tabs */}
                <InputSelector
                  currentType={currentType}
                  onChange={setCurrentType}
                  disabled={loading}
                />

                {/* Active Analyzer Form */}
                <div className="pt-2">
                  {currentType === 'url' && (
                    <UrlAnalyzer onAnalyze={handleAnalyzeUrl} loading={loading} />
                  )}
                  {currentType === 'message' && (
                    <MessageAnalyzer onAnalyze={handleAnalyzeMessage} loading={loading} />
                  )}
                  {currentType === 'email' && (
                    <EmailAnalyzer onAnalyze={handleAnalyzeEmail} loading={loading} />
                  )}
                  {currentType === 'qr' && (
                    <QrUploader onAnalyze={handleAnalyzeQr} loading={loading} />
                  )}
                  {currentType === 'webpage' && (
                    <WebpageAnalyzer onAnalyze={handleAnalyzeWebpage} loading={loading} />
                  )}
                  {currentType === 'social' && (
                    <SocialAnalyzer onAnalyze={handleAnalyzeSocial} loading={loading} />
                  )}
                </div>

                {/* Real-time Progress Animation when Analyzing */}
                {loading && <AnalysisProgress input_type={currentType} />}
              </HudBracket>
            </div>

          </div>
        )}
      </main>

      {/* Clean Minimal Footer */}
      <footer className="relative z-10 w-full border-t border-pine-600/50 bg-[#051F20]/90 backdrop-blur-md py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-pine-300/70">
          <div className="flex items-center space-x-2 font-mono text-[11px] text-pine-300/80">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>CyberShield Active Threat Defense Engine</span>
          </div>

          <div className="text-center sm:text-right text-pine-300/70">
            Explainable Multi-Vector Threat Intelligence & Privacy Defense
          </div>
        </div>
      </footer>

      {/* Modals */}
      <HistoryModal
        isOpen={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onSelectAnalysis={(selected) => {
          setResult(selected);
          setHistoryOpen(false);
          scrollToAnalyzer();
        }}
      />

      <ReportModal
        isOpen={reportOpen}
        onClose={() => setReportOpen(false)}
        initialTarget={reportInitialTarget}
        initialCategory={reportInitialCategory}
      />
    </div>
  );
};

export default App;
