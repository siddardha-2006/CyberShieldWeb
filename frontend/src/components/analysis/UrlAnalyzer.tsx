import React, { useState } from 'react';
import { Globe, ArrowRight, ShieldCheck } from 'lucide-react';

interface UrlAnalyzerProps {
  onAnalyze: (url: string) => void;
  loading: boolean;
}

export const UrlAnalyzer: React.FC<UrlAnalyzerProps> = ({ onAnalyze, loading }) => {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-2">
          Enter Website URL to Scan
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
            <Globe className="h-5 w-5 text-pine-300/80" />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. https://example-secure-login.com/verify?id=9021"
            disabled={loading}
            className="w-full pl-11 pr-4 py-3.5 bg-pine-800/90 border border-pine-600 rounded-xl text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 focus:ring-2 focus:ring-pine-300/20 transition-all font-mono shadow-inner"
          />
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
        <div className="text-xs text-pine-300/80 flex items-center space-x-1.5 self-start sm:self-center">
          <ShieldCheck className="w-4 h-4 text-pine-300" />
          <span>Scans DNS, URL redirects, phishing keywords & threat feeds</span>
        </div>

        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <span>{loading ? 'Analyzing Content...' : 'Scan URL Now'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
