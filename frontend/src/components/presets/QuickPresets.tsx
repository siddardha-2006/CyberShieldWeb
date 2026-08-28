import React, { useEffect, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { SamplePreset, InputType } from '../../types';
import { apiService } from '../../services/api';

interface QuickPresetsProps {
  onSelectPreset: (type: InputType, payload: Record<string, any>) => void;
  disabled?: boolean;
}

export const QuickPresets: React.FC<QuickPresetsProps> = ({ onSelectPreset, disabled = false }) => {
  const [presets, setPresets] = useState<SamplePreset[]>([]);

  useEffect(() => {
    apiService.getSamples().then((res) => {
      if (res.samples) setPresets(res.samples);
    }).catch(() => {
      // Fallback local presets
      setPresets([
        {
          id: 'bank_kyc_phish',
          title: 'Fake Bank KYC SMS (Phishing)',
          type: 'message',
          severity_expected: 'critical',
          payload: {
            text: 'URGENT: State Bank account blocked due to pending KYC. Click link to verify OTP within 24 hours: https://sbi-secure-kyc-update.com/login',
            sender: '+18005550199',
          },
        },
        {
          id: 'legitimate_service',
          title: 'Official Python Documentation (Safe)',
          type: 'url',
          severity_expected: 'safe',
          payload: {
            url: 'https://docs.python.org/3/library/asyncio.html',
          },
        },
        {
          id: 'spoofed_email',
          title: 'CEO Wire Transfer Request (BEC Scam)',
          type: 'email',
          severity_expected: 'critical',
          payload: {
            sender: 'ceo@corporate-tech.com',
            reply_to: 'ceo-direct-office@gmail.com',
            subject: 'CONFIDENTIAL: Wire Transfer Required',
            body: 'Are you at your desk? I need an urgent wire transfer of $45,000 executed today.',
          },
        },
      ]);
    });
  }, []);

  if (!presets.length) return null;

  return (
    <div className="pt-6 border-t border-pine-600/50">
      <div className="flex items-center space-x-2 mb-3">
        <Sparkles className="w-4 h-4 text-pine-300" />
        <span className="text-xs font-bold text-pine-300 uppercase tracking-wider">
          Quick Test Examples (Click to test instantly)
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
        {presets.map((p) => {
          const isCritical = p.severity_expected === 'critical';
          const isSafe = p.severity_expected === 'safe';
          return (
            <button
              key={p.id}
              disabled={disabled}
              onClick={() => onSelectPreset(p.type, p.payload)}
              className="p-3.5 text-left rounded-xl bg-pine-800/80 hover:bg-pine-700/90 border border-pine-600 hover:border-pine-300/80 transition-all group disabled:opacity-50 disabled:cursor-not-allowed flex flex-col justify-between shadow-sm"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase bg-pine-900 text-pine-300 border border-pine-600/80 font-semibold">
                  {p.type}
                </span>
                <span className={`text-[11px] font-semibold uppercase ${
                  isCritical ? 'text-cyber-danger' : isSafe ? 'text-cyber-safe' : 'text-cyber-warn'
                }`}>
                  {isCritical ? 'Malicious' : isSafe ? 'Safe' : 'Suspicious'}
                </span>
              </div>
              <span className="text-xs font-medium text-pine-100 group-hover:text-white transition-colors truncate">
                {p.title}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
