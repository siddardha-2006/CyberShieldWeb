import React, { useEffect, useRef } from 'react';
import { Severity } from '../../types';

interface CyberOrbProps {
  severity?: Severity;
  isAnalyzing?: boolean;
  score?: number;
}

export const CyberOrb: React.FC<CyberOrbProps> = ({ severity = 'safe', isAnalyzing = false, score }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let angle = 0;
    let pulseTime = 0;

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const radius = 80; // Scaled to prevent any ray overflow

      // Exact color mapping from pine palette
      let primaryGlow = 'rgba(35, 83, 71, ';       // #235347 Emerald
      let coreWarmth = 'rgba(142, 182, 155, ';     // #8EB69B Sage Mint
      let rayColor = 'rgba(218, 241, 222, ';       // #DAF1DE Pale Ice Mint

      if (severity === 'critical') {
        primaryGlow = 'rgba(230, 57, 70, ';
        coreWarmth = 'rgba(255, 107, 107, ';
        rayColor = 'rgba(255, 200, 200, ';
      } else if (severity === 'high_risk') {
        primaryGlow = 'rgba(233, 196, 106, ';
        coreWarmth = 'rgba(233, 196, 106, ';
        rayColor = 'rgba(255, 230, 200, ';
      } else if (severity === 'suspicious') {
        primaryGlow = 'rgba(142, 182, 155, ';
        coreWarmth = 'rgba(142, 182, 155, ';
      }

      // 1. Outer Ethereal Atmosphere Nebula (Bubble)
      const outerGrad = ctx.createRadialGradient(
        centerX, 
        centerY, 
        radius * 0.5, 
        centerX, 
        centerY, 
        radius * 1.5
      );
      outerGrad.addColorStop(0, primaryGlow + '0.45)');
      outerGrad.addColorStop(0.5, primaryGlow + '0.15)');
      outerGrad.addColorStop(1, 'transparent');
      ctx.fillStyle = outerGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.5, 0, Math.PI * 2);
      ctx.fill();

      // 2. Radiant Light Rays (bounded within canvas)
      ctx.save();
      ctx.translate(centerX, centerY);
      
      const rayAngles = [
        -Math.PI / 4,         // Top-right
        (3 * Math.PI) / 4,    // Bottom-left
        Math.PI / 4,          // Bottom-right
        -(3 * Math.PI) / 4    // Top-left
      ];

      for (let i = 0; i < rayAngles.length; i++) {
        const baseAngle = rayAngles[i] + Math.sin(pulseTime * 0.5) * 0.05;
        ctx.save();
        ctx.rotate(baseAngle);

        const rayGrad = ctx.createLinearGradient(0, 0, radius * 1.8, 0);
        rayGrad.addColorStop(0, rayColor + '0.95)');
        rayGrad.addColorStop(0.3, coreWarmth + '0.6)');
        rayGrad.addColorStop(0.7, primaryGlow + '0.2)');
        rayGrad.addColorStop(1, 'transparent');

        ctx.fillStyle = rayGrad;
        ctx.beginPath();
        ctx.moveTo(0, -2.5);
        ctx.lineTo(radius * 1.8, -0.8);
        ctx.lineTo(radius * 1.8, 0.8);
        ctx.lineTo(0, 2.5);
        ctx.closePath();
        ctx.fill();
        ctx.restore();
      }
      ctx.restore();

      // 3. Atmospheric Rings
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.2, 0, Math.PI * 2);
      ctx.strokeStyle = primaryGlow + '0.7)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.02, 0, Math.PI * 2);
      ctx.strokeStyle = rayColor + '0.25)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // 4. Geodesic Triangle Mesh / Dark Faceted Sphere
      const points: { x: number; y: number; z: number }[] = [];
      const numRings = 7;
      const numSegments = 12;

      for (let r = 0; r <= numRings; r++) {
        const phi = (Math.PI * r) / numRings;
        for (let s = 0; s < numSegments; s++) {
          const theta = (2 * Math.PI * s) / numSegments + angle;
          const x = radius * Math.sin(phi) * Math.cos(theta);
          const y = radius * Math.cos(phi);
          const z = radius * Math.sin(phi) * Math.sin(theta);
          points.push({ x, y, z });
        }
      }

      ctx.strokeStyle = primaryGlow + (isAnalyzing ? '0.95)' : '0.65)');
      ctx.lineWidth = 1.2;

      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        if (p.z > -25) {
          const nextInRing = (i % numSegments === numSegments - 1) ? i - numSegments + 1 : i + 1;
          const nextRing = i + numSegments;

          if (points[nextInRing]) {
            ctx.beginPath();
            ctx.moveTo(centerX + p.x, centerY + p.y);
            ctx.lineTo(centerX + points[nextInRing].x, centerY + points[nextInRing].y);
            ctx.stroke();
          }

          if (nextRing < points.length) {
            ctx.beginPath();
            ctx.moveTo(centerX + p.x, centerY + p.y);
            ctx.lineTo(centerX + points[nextRing].x, centerY + points[nextRing].y);
            ctx.stroke();
          }
        }
      }

      // 5. Inner Luminous Core
      const coreGrad = ctx.createRadialGradient(
        centerX - radius * 0.15, 
        centerY - radius * 0.15, 
        3, 
        centerX, 
        centerY, 
        radius * 0.75
      );
      coreGrad.addColorStop(0, coreWarmth + '0.98)');
      coreGrad.addColorStop(0.35, primaryGlow + '0.55)');
      coreGrad.addColorStop(0.8, 'transparent');

      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 0.78, 0, Math.PI * 2);
      ctx.fill();

      // 6. Glowing node points
      for (let j = 0; j < points.length; j += 2) {
        const p = points[j];
        if (p.z > 30) {
          const nodeGlow = ctx.createRadialGradient(
            centerX + p.x, centerY + p.y, 1,
            centerX + p.x, centerY + p.y, 5
          );
          nodeGlow.addColorStop(0, rayColor + '1)');
          nodeGlow.addColorStop(0.5, coreWarmth + '0.6)');
          nodeGlow.addColorStop(1, 'transparent');
          ctx.fillStyle = nodeGlow;
          ctx.beginPath();
          ctx.arc(centerX + p.x, centerY + p.y, 4, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      angle += isAnalyzing ? 0.025 : 0.007;
      pulseTime += 0.03;
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [severity, isAnalyzing]);

  return (
    <div className="relative flex items-center justify-center p-0 my-0 overflow-hidden">
      {/* Outer ambient blur shadow */}
      <div 
        className={`absolute w-56 h-56 rounded-full filter blur-2xl opacity-30 transition-all duration-700 pointer-events-none ${
          severity === 'critical' 
            ? 'bg-cyber-danger' 
            : severity === 'high_risk' 
            ? 'bg-cyber-warn' 
            : 'bg-cyber-teal'
        }`} 
      />
      
      <canvas 
        ref={canvasRef} 
        width={300} 
        height={300} 
        className="relative z-10 w-[220px] h-[220px] sm:w-[260px] sm:h-[260px] block" 
      />

      {/* Center status badge if score provided */}
      {score !== undefined && (
        <div className="absolute z-20 flex flex-col items-center justify-center pointer-events-none bg-cyber-dark/90 px-3.5 py-1.5 rounded-lg border border-cyber-sand/50 shadow-teal-glow backdrop-blur-md">
          <span className="text-2xl sm:text-3xl font-bold font-mono tracking-wider text-cyber-ice drop-shadow-md">
            {score}
          </span>
          <span className="text-[9px] tracking-widest uppercase font-mono text-cyber-sand">
            RISK INDEX
          </span>
        </div>
      )}
    </div>
  );
};
