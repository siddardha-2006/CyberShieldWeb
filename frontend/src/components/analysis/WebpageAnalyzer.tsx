import React, { useState } from 'react';
import { Layout, ArrowRight, Code } from 'lucide-react';

interface WebpageAnalyzerProps {
  onAnalyze: (url: string, htmlContent?: string) => void;
  loading: boolean;
}

export const WebpageAnalyzer: React.FC<WebpageAnalyzerProps> = ({ onAnalyze, loading }) => {
  const [url, setUrl] = useState('');
  const [html, setHtml] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim(), html.trim() || undefined);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-2">
          Target Webpage URL
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
            <Layout className="h-5 w-5 text-pine-300/80" />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://portal-sso-verify.org/login"
            disabled={loading}
            className="w-full pl-11 pr-4 py-3.5 bg-pine-800/90 border border-pine-600 rounded-xl text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 font-mono transition-all shadow-inner"
          />
        </div>
      </div>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-xs text-pine-300/80 hover:text-pine-100 flex items-center space-x-1.5 underline"
        >
          <Code className="w-3.5 h-3.5" />
          <span>{showAdvanced ? 'Hide Raw HTML Inspector' : 'Optional: Paste Raw HTML Code'}</span>
        </button>
      </div>

      {showAdvanced && (
        <div>
          <label className="block text-xs font-semibold text-pine-300/80 uppercase tracking-wider mb-1">
            Raw HTML Markup
          </label>
          <textarea
            rows={4}
            value={html}
            onChange={(e) => setHtml(e.target.value)}
            placeholder="Paste HTML source markup here to analyze forms, script tags, and hidden exfiltration inputs..."
            disabled={loading}
            className="w-full p-3.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 font-mono focus:outline-none focus:border-pine-300 transition-all resize-none shadow-inner"
          />
        </div>
      )}

      <div className="flex justify-end pt-1">
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <span>{loading ? 'Analyzing Webpage DOM...' : 'Scan Webpage Now'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
