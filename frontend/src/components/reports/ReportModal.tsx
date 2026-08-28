import React, { useState } from 'react';
import { X, AlertOctagon, CheckCircle2, ArrowRight } from 'lucide-react';
import { apiService } from '../../services/api';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialTarget?: string;
  initialCategory?: string;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  initialTarget = '',
  initialCategory = 'phishing',
}) => {
  const [target, setTarget] = useState(initialTarget);
  const [category, setCategory] = useState(initialCategory);
  const [comments, setComments] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    try {
      await apiService.submitReport({
        target: target.trim(),
        threat_category: category,
        user_comments: comments.trim() || undefined,
      });
      setSubmitted(true);
    } catch (err) {
      alert('Error logging threat indicator.');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setSubmitted(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-pine-900/80 backdrop-blur-md">
      <div className="w-full max-w-lg bg-pine-700 border border-pine-300/40 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-pine-600 bg-pine-800">
          <div className="flex items-center space-x-2.5">
            <AlertOctagon className="w-5 h-5 text-pine-300" />
            <h3 className="text-base font-bold text-pine-100">
              Report Threat Indicator
            </h3>
          </div>
          <button
            onClick={handleClose}
            className="p-1.5 rounded-lg text-pine-300 hover:text-white hover:bg-pine-600 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        {submitted ? (
          <div className="p-8 text-center space-y-4">
            <CheckCircle2 className="w-14 h-14 text-cyber-safe mx-auto animate-bounce" />
            <h4 className="text-xl font-bold text-pine-100">
              Threat Successfully Reported
            </h4>
            <p className="text-xs text-pine-300/90 max-w-sm mx-auto">
              Cryptographic indicator submitted to the Cyber Shield threat feed for community protection.
            </p>
            <button
              onClick={handleClose}
              className="px-6 py-2.5 rounded-xl pine-btn-primary font-bold text-xs shadow-glow-mint"
            >
              Close Window
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div>
              <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1.5">
                Malicious URL, Phone, or Email *
              </label>
              <input
                type="text"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://fake-bank-login.com"
                className="w-full px-3.5 py-2.5 bg-pine-800 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 font-mono transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1.5">
                Threat Classification
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-pine-800 border border-pine-600 rounded-xl text-xs text-pine-100 focus:outline-none focus:border-pine-300 font-medium"
              >
                <option value="phishing">Phishing & Credential Theft</option>
                <option value="financial_fraud">Financial / Banking Scam</option>
                <option value="malware">Malware Payload / Trojan</option>
                <option value="social_engineering">Social Engineering & Coercion</option>
                <option value="qr_scam">QR Code Manipulation</option>
                <option value="impersonation">Brand / Executive Impersonation</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-1.5">
                Additional Notes (Optional)
              </label>
              <textarea
                rows={3}
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                placeholder="Where did you receive this link? Any details help our community intelligence..."
                className="w-full p-3 bg-pine-800 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 transition-all resize-none"
              />
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={loading || !target.trim()}
                className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
              >
                <span>{loading ? 'Submitting...' : 'Submit Threat Report'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
