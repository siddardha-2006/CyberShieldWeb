import React, { useEffect, useState } from 'react';
import { X, History, ExternalLink } from 'lucide-react';
import { AnalysisResponse } from '../../types';
import { apiService } from '../../services/api';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectAnalysis: (analysis: AnalysisResponse) => void;
}

export const HistoryModal: React.FC<HistoryModalProps> = ({ isOpen, onClose, onSelectAnalysis }) => {
  const [history, setHistory] = useState<AnalysisResponse[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      apiService
        .getHistory()
        .then((res) => {
          setHistory(res.analyses || []);
        })
        .finally(() => setLoading(false));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/40">Critical</span>;
      case 'high_risk':
        return <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase bg-cyber-warn/20 text-cyber-warn border border-cyber-warn/40">High Risk</span>;
      case 'suspicious':
        return <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase bg-cyber-warn/20 text-cyber-warn border border-cyber-warn/40">Suspicious</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase bg-cyber-safe/20 text-cyber-safe border border-cyber-safe/40">Safe</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-pine-900/80 backdrop-blur-md">
      <div className="w-full max-w-3xl max-h-[85vh] bg-pine-700 border border-pine-300/40 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-pine-600 bg-pine-800">
          <div className="flex items-center space-x-2.5">
            <History className="w-5 h-5 text-pine-300" />
            <h3 className="text-base font-bold text-pine-100">
              Audit Trail & Scan History
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-pine-300 hover:text-white hover:bg-pine-600 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-3 flex-1">
          {loading ? (
            <div className="text-center py-12 text-sm text-pine-300">
              Loading past scan records...
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-12 text-sm text-pine-300/70">
              No previous analyses found. Submit your first URL, message, or QR code above.
            </div>
          ) : (
            history.map((item) => (
              <div
                key={item.analysis_id}
                onClick={() => {
                  onSelectAnalysis(item);
                  onClose();
                }}
                className="p-4 rounded-xl bg-pine-800/90 border border-pine-600 hover:border-pine-300/80 hover:bg-pine-800 transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-pine-900 text-pine-300 border border-pine-600">
                      {item.input_type}
                    </span>
                    {getSeverityBadge(item.assessment?.severity || 'safe')}
                    <span className="text-xs text-pine-300/60">
                      {new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div className="text-sm font-semibold text-pine-100">
                    {item.assessment?.category || 'Threat Assessment'}
                  </div>
                  <div className="text-xs text-pine-300/70 font-mono truncate max-w-md">
                    HMAC: {item.indicator_hmac}
                  </div>
                </div>

                <div className="flex items-center space-x-4 self-end sm:self-center">
                  <div className="text-right">
                    <div className="text-xl font-black font-mono text-pine-100">
                      {item.assessment?.risk_score}/100
                    </div>
                    <div className="text-[10px] text-pine-300 uppercase tracking-wider font-semibold">Risk Index</div>
                  </div>
                  <ExternalLink className="w-4 h-4 text-pine-300" />
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
