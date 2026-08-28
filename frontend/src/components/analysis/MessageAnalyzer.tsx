import React, { useState } from 'react';
import { ArrowRight, Phone } from 'lucide-react';

interface MessageAnalyzerProps {
  onAnalyze: (text: string, sender?: string) => void;
  loading: boolean;
}

export const MessageAnalyzer: React.FC<MessageAnalyzerProps> = ({ onAnalyze, loading }) => {
  const [text, setText] = useState('');
  const [sender, setSender] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (text.trim()) {
      onAnalyze(text.trim(), sender.trim() || undefined);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-semibold text-pine-300 uppercase tracking-wider">
            SMS / Text Message Content
          </label>
          <span className="text-[10px] text-indigo-300 bg-indigo-950/60 border border-indigo-500/30 px-2 py-0.5 rounded-full flex items-center space-x-1 font-mono">
            🌐 Auto-Translates Regional Text
          </span>
        </div>
        <textarea
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste suspicious text message (e.g. 'URGENT: Your account is suspended. Click link to verify OTP: http://fake-bank.com')..."
          disabled={loading}
          className="w-full p-4 bg-pine-800/90 border border-pine-600 rounded-xl text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 focus:ring-2 focus:ring-pine-300/20 transition-all resize-none shadow-inner"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-pine-300/80 uppercase tracking-wider mb-1">
          Sender Phone / Header ID (Optional)
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Phone className="h-4 w-4 text-pine-300/80" />
          </div>
          <input
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="e.g. +1-800-555-0199 or BANKALERT"
            disabled={loading}
            className="w-full pl-10 pr-4 py-2.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 font-mono transition-all"
          />
        </div>
      </div>

      <div className="flex justify-end pt-2">
        <button
          type="submit"
          disabled={loading || !text.trim()}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <span>{loading ? 'Analyzing Message...' : 'Scan Message Now'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
