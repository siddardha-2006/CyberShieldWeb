import React, { useState, useRef } from 'react';
import { QrCode, Upload, ArrowRight, X } from 'lucide-react';

interface QrUploaderProps {
  onAnalyze: (data: { image_base64?: string; decoded_payload?: string }) => void;
  loading: boolean;
}

export const QrUploader: React.FC<QrUploaderProps> = ({ onAnalyze, loading }) => {
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [manualPayload, setManualPayload] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const clearImage = () => {
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (imagePreview || manualPayload.trim()) {
      onAnalyze({
        image_base64: imagePreview || undefined,
        decoded_payload: manualPayload.trim() || undefined,
      });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
        {/* Upload Box */}
        <div>
          <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider mb-2">
            Upload QR Code Image
          </label>
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-pine-600 hover:border-pine-300 rounded-2xl p-6 flex flex-col items-center justify-center cursor-pointer bg-pine-800/80 hover:bg-pine-800 transition-all text-center group"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleFileChange}
              disabled={loading}
            />
            {imagePreview ? (
              <div className="relative group/prev">
                <img
                  src={imagePreview}
                  alt="QR Preview"
                  className="max-h-36 rounded-xl border border-pine-300/80 object-contain shadow-glow-mint"
                />
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    clearImage();
                  }}
                  className="absolute -top-2 -right-2 bg-cyber-danger text-white rounded-full p-1 shadow hover:scale-110 transition-transform"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <>
                <Upload className="w-9 h-9 text-pine-300 group-hover:scale-110 transition-transform mb-2" />
                <span className="text-xs font-medium text-pine-100">Click or drag QR image here</span>
                <span className="text-[11px] text-pine-300/60 mt-1">PNG, JPG, WEBP formats</span>
              </>
            )}
          </div>
        </div>

        {/* Or direct payload input */}
        <div className="space-y-2">
          <label className="block text-xs font-semibold text-pine-300 uppercase tracking-wider">
            Or Paste Decoded Text / Link
          </label>
          <textarea
            rows={5}
            value={manualPayload}
            onChange={(e) => setManualPayload(e.target.value)}
            placeholder="http://192.168.1.10/login.php or WIFI:S:Guest;P:password;;"
            disabled={loading}
            className="w-full p-3.5 bg-pine-800/90 border border-pine-600 rounded-xl text-xs text-pine-100 placeholder-pine-300/30 focus:outline-none focus:border-pine-300 font-mono transition-all resize-none shadow-inner"
          />
        </div>
      </div>

      <div className="flex justify-end pt-1">
        <button
          type="submit"
          disabled={loading || (!imagePreview && !manualPayload.trim())}
          className="w-full sm:w-auto px-7 py-3 rounded-xl pine-btn-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-glow-mint"
        >
          <QrCode className="w-4 h-4" />
          <span>{loading ? 'Decoding QR Code...' : 'Decode & Scan QR'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </form>
  );
};
