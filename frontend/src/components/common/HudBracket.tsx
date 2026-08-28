import React from 'react';

interface HudBracketProps {
  children: React.ReactNode;
  className?: string;
}

export const HudBracket: React.FC<HudBracketProps> = ({ children, className = '' }) => {
  return (
    <div className={`relative p-6 sm:p-7 pine-card rounded-2xl ${className}`}>
      {/* Subtle modern corner accents */}
      <span className="absolute top-3 left-3 w-2.5 h-2.5 border-t-2 border-l-2 border-pine-300/80 rounded-tl pointer-events-none" />
      <span className="absolute top-3 right-3 w-2.5 h-2.5 border-t-2 border-r-2 border-pine-300/80 rounded-tr pointer-events-none" />
      <span className="absolute bottom-3 left-3 w-2.5 h-2.5 border-b-2 border-l-2 border-pine-300/80 rounded-bl pointer-events-none" />
      <span className="absolute bottom-3 right-3 w-2.5 h-2.5 border-b-2 border-r-2 border-pine-300/80 rounded-br pointer-events-none" />
      {children}
    </div>
  );
};
