import React from 'react';
import { Globe, MessageSquare, Mail, QrCode, Layout, Share2 } from 'lucide-react';
import { InputType } from '../../types';

interface InputSelectorProps {
  currentType: InputType;
  onChange: (type: InputType) => void;
  disabled?: boolean;
}

export const InputSelector: React.FC<InputSelectorProps> = ({ currentType, onChange, disabled = false }) => {
  const tabs: { 
    type: InputType; 
    label: string; 
    icon: React.FC<{ className?: string }>;
    activeColor: string;
    iconColor: string;
  }[] = [
    { 
      type: 'url', 
      label: 'Link / URL', 
      icon: Globe,
      activeColor: 'bg-emerald-900/90 text-emerald-100 border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)]',
      iconColor: 'text-emerald-400'
    },
    { 
      type: 'message', 
      label: 'SMS / Text', 
      icon: MessageSquare,
      activeColor: 'bg-sky-900/90 text-sky-100 border-sky-400 shadow-[0_0_15px_rgba(56,189,248,0.3)]',
      iconColor: 'text-sky-400'
    },
    { 
      type: 'email', 
      label: 'Email', 
      icon: Mail,
      activeColor: 'bg-purple-900/90 text-purple-100 border-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.3)]',
      iconColor: 'text-purple-400'
    },
    { 
      type: 'qr', 
      label: 'QR Code', 
      icon: QrCode,
      activeColor: 'bg-amber-900/90 text-amber-100 border-amber-400 shadow-[0_0_15px_rgba(251,191,36,0.3)]',
      iconColor: 'text-amber-400'
    },
    { 
      type: 'webpage', 
      label: 'Web DOM', 
      icon: Layout,
      activeColor: 'bg-cyan-900/90 text-cyan-100 border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.3)]',
      iconColor: 'text-cyan-400'
    },
    { 
      type: 'social', 
      label: 'Social Post', 
      icon: Share2,
      activeColor: 'bg-fuchsia-900/90 text-fuchsia-100 border-fuchsia-400 shadow-[0_0_15px_rgba(232,121,249,0.3)]',
      iconColor: 'text-fuchsia-400'
    },
  ];

  return (
    <div className="w-full grid grid-cols-3 sm:grid-cols-6 gap-1.5 mb-5 pb-3 border-b border-pine-600/40">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = currentType === tab.type;
        return (
          <button
            key={tab.type}
            disabled={disabled}
            onClick={() => onChange(tab.type)}
            className={`flex flex-col sm:flex-row items-center justify-center space-y-1 sm:space-y-0 sm:space-x-1.5 px-2 py-2 rounded-xl text-xs font-semibold tracking-wide transition-all border ${
              isActive
                ? tab.activeColor
                : 'text-pine-300/70 hover:text-pine-100 hover:bg-pine-800/80 border-transparent'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
          >
            <Icon className={`w-3.5 h-3.5 ${isActive ? tab.iconColor : 'text-pine-300/60'}`} />
            <span className="truncate text-[11px] sm:text-xs">{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
};
