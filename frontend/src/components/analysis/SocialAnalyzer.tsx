import React, { useState } from 'react';
import { ArrowRight } from 'lucide-react';

interface SocialAnalyzerProps {
  onAnalyze: (text: string, platform?: string) => void;
  loading: boolean;
}

export const SocialAnalyzer: React.FC<SocialAnalyzerProps> = ({ onAnalyze, loading }) => {
  const [text, setText] = useState('');
  const [platform, setPlatform] = useState('telegram');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (text.trim()) {
      onAnalyze(text.trim(), platform);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-semibold text-pine-300 uppercase tracking-wider">
            Social Media DM / Post Content
          </label>
          <span className="text-[10px] text-indigo-300 bg-indigo-950/60 border border-indigo-500/30 px-2 py-0.5 rounded-full flex items-center space-x-1 font-mono">
            🌐 Any Regional Language
          </span>
        </div>
        <textarea
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste social media post, Discord DM, Telegram announcement, or WhatsApp forward..."
          disabled={loading}
          className="w-full p-4 bg-pine-800/90 border border-pine-600 rounded-xl text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 transition-all resize-none shadow-inner"
        />
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <span className="text-xs font-semibold text-pine-300 uppercase">Platform context:</span>
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            disabled={loading}
            className="bg-pine-800 border border-pine-600 rounded-xl px-3.5 py-2 text-xs text-pine-100 focus:outline-none focus:border-pine-300 font-medium"
          >
            <option value="telegram">Telegram</option>
            <option value="discord">Discord</option>
            <option value="twitter">X / Twitter</option>
            <option value="whatsapp">WhatsApp</option>
            <option value="linkedin">LinkedIn</option>
            <option value="generic">Other Platform</option>
          </select>
        </div>

        <button
          type="submit"
          disabled={loading || !text.trim()}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <span>{loading ? 'Analyzing Intent...' : 'Scan Social Post'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
