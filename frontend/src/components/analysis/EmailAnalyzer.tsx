import React, { useState } from 'react';
import { ArrowRight, Mail, Sparkles, SlidersHorizontal } from 'lucide-react';

interface EmailAnalyzerProps {
  onAnalyze: (data: {
    raw_email?: string;
    sender?: string;
    subject?: string;
    body?: string;
    reply_to?: string;
    headers?: Record<string, string>;
  }) => void;
  loading: boolean;
}

export const EmailAnalyzer: React.FC<EmailAnalyzerProps> = ({ onAnalyze, loading }) => {
  const [mode, setMode] = useState<'full' | 'manual'>('full');
  
  // Full email mode
  const [rawEmail, setRawEmail] = useState('');

  // Manual fields mode
  const [sender, setSender] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === 'full') {
      if (rawEmail.trim()) {
        onAnalyze({ raw_email: rawEmail.trim() });
      }
    } else {
      if (body.trim()) {
        onAnalyze({
          sender: sender.trim() || 'unknown@unverified.org',
          subject: subject.trim(),
          body: body.trim(),
          reply_to: replyTo.trim() || undefined,
        });
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Header Mode Switcher & Multilingual Badge */}
      <div className="flex items-center justify-between pb-2 border-b border-pine-600/40">
        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={() => setMode('full')}
            className={`px-3 py-1 rounded-lg text-xs font-bold transition-all flex items-center space-x-1.5 ${
              mode === 'full'
                ? 'bg-purple-900/80 text-purple-200 border border-purple-400 shadow-sm'
                : 'text-pine-300/70 hover:text-pine-100 hover:bg-pine-800/60'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Full Email Paste (NLP Auto-Extract)</span>
          </button>

          <button
            type="button"
            onClick={() => setMode('manual')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all flex items-center space-x-1.5 ${
              mode === 'manual'
                ? 'bg-purple-900/80 text-purple-200 border border-purple-400 shadow-sm'
                : 'text-pine-300/70 hover:text-pine-100 hover:bg-pine-800/60'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>Separate Fields</span>
          </button>
        </div>

        <span className="text-[10px] text-indigo-300 bg-indigo-950/60 border border-indigo-500/30 px-2 py-0.5 rounded-full flex items-center space-x-1 font-mono">
          <Sparkles className="w-3 h-3 text-indigo-400" />
          <span>AI Header Extraction</span>
        </span>
      </div>

      {mode === 'full' ? (
        /* Full Single-Box Email Paste Area */
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-pine-300 uppercase tracking-wider">
              Paste Complete Email Message
            </label>
            <span className="text-[11px] text-pine-300/60 font-sans">
              Paste directly from Outlook, Gmail, or Apple Mail
            </span>
          </div>

          <textarea
            rows={7}
            required
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            placeholder={`From: "HR Payroll Department" <payroll-update@secure-portal.xyz>\nSubject: URGENT: Complete your mandatory tax compliance update\nDate: 29 Aug 2026 09:30:00\n\nDear Employee,\nYour account will be suspended within 24 hours. Click the link below to verify your login credentials:\nhttps://payroll.verify-employee-login.com\n\nBest Regards,\nHR Team`}
            disabled={loading}
            className="w-full p-4 bg-pine-800/90 border border-pine-600 rounded-xl text-xs sm:text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-purple-400 focus:ring-2 focus:ring-purple-400/20 font-mono transition-all resize-none shadow-inner leading-relaxed"
          />

          <div className="p-2.5 rounded-xl bg-purple-950/40 border border-purple-500/30 text-[11px] text-purple-200/90 flex items-start space-x-2">
            <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
            <span>
              CyberShield automatically identifies the sender address, subject line, display-name spoofing, embedded URLs, and evaluates NLP phishing intent in one scan.
            </span>
          </div>
        </div>
      ) : (
        /* Manual Separate Fields Form */
        <div className="space-y-3 animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1">
                Sender Email (From) *
              </label>
              <input
                type="email"
                required
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="e.g. security-team@account-service.com"
                disabled={loading}
                className="w-full px-3.5 py-2.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-purple-400 font-mono transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-pine-300/80 uppercase tracking-wider mb-1">
                Reply-To Email (If Different)
              </label>
              <input
                type="email"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                placeholder="e.g. attacker-mailbox@gmail.com"
                disabled={loading}
                className="w-full px-3.5 py-2.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-purple-400 font-mono transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1">
              Subject Line
            </label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. URGENT: Action Required on Your Payroll Account"
              disabled={loading}
              className="w-full px-3.5 py-2.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-purple-400 font-mono transition-all"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1">
              Email Body Text *
            </label>
            <textarea
              rows={4}
              required
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Paste email body or text content..."
              disabled={loading}
              className="w-full p-3.5 bg-pine-800/90 border border-pine-600 rounded-xl text-sm text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-purple-400 transition-all resize-none shadow-inner"
            />
          </div>
        </div>
      )}

      <div className="flex justify-end pt-1">
        <button
          type="submit"
          disabled={loading || (mode === 'full' ? !rawEmail.trim() : !body.trim())}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <span>{loading ? 'Analyzing Email Telemetry...' : 'Scan Complete Email'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
