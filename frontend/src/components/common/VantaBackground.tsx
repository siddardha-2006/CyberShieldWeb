import React, { useEffect, useRef } from 'react';

export const VantaBackground: React.FC = () => {
  const vantaRef = useRef<HTMLDivElement | null>(null);
  const vantaEffectRef = useRef<any>(null);

  useEffect(() => {
    let isMounted = true;
    let timer: any = null;

    const loadScript = (src: string): Promise<void> => {
      return new Promise((resolve) => {
        const existing = document.querySelector(`script[src="${src}"]`);
        if (existing) {
          resolve();
          return;
        }
        const script = document.createElement('script');
        script.src = src;
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => resolve(); // Don't crash if offline
        document.head.appendChild(script);
      });
    };

    const setupVanta = async () => {
      try {
        // Ensure Three.js is loaded first
        if (!(window as any).THREE) {
          await loadScript('https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js');
        }

        // Ensure Vanta.NET is loaded
        if (!(window as any).VANTA?.NET) {
          await loadScript('https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js');
        }

        if (!isMounted || !vantaRef.current || vantaEffectRef.current) return;

        const THREE = (window as any).THREE;
        const VANTA = (window as any).VANTA;

        if (VANTA && VANTA.NET && THREE) {
          vantaEffectRef.current = VANTA.NET({
            el: vantaRef.current,
            THREE: THREE,
            mouseControls: true,
            touchControls: true,
            gyroControls: false,
            minHeight: 200.0,
            minWidth: 200.0,
            scale: 1.0,
            scaleMobile: 1.0,
            color: 0xffffff,
            backgroundColor: 0x1c5f2f,
            points: 10.0,
            maxDistance: 20.0,
            spacing: 17.0,
            showDots: true,
          });
        }
      } catch (err) {
        console.warn('Vanta initialization skipped/fallback:', err);
      }
    };

    setupVanta();

    return () => {
      isMounted = false;
      if (timer) clearTimeout(timer);
      if (vantaEffectRef.current) {
        try {
          vantaEffectRef.current.destroy();
        } catch (e) {
          // ignore
        }
        vantaEffectRef.current = null;
      }
    };
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-[#051F20]">
      {/* 3D Vanta Animated NET Canvas Element */}
      <div ref={vantaRef} className="absolute inset-0 w-full h-full" />

      {/* Cybernetic Pine Gradient Overlay for Crisp Readability & Contrast */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#051F20]/75 via-[#0B2B26]/80 to-[#051F20]/90 backdrop-blur-[1px]" />
    </div>
  );
};
