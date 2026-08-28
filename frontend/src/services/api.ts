import axios from 'axios';
import { AnalysisResponse, SamplePreset } from '../types';

const apiBase = import.meta.env.VITE_API_URL 
  ? `${import.meta.env.VITE_API_URL.replace(/\/$/, '')}/api/v1` 
  : '/api/v1';

const apiClient = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 35000,
});

export const apiService = {
  // Analysis endpoints
  analyzeUrl: async (url: string): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/url', { url });
    return res.data;
  },

  analyzeMessage: async (text: string, sender?: string): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/message', { text, sender });
    return res.data;
  },

  analyzeEmail: async (data: {
    raw_email?: string;
    sender?: string;
    subject?: string;
    body?: string;
    reply_to?: string;
    headers?: Record<string, string>;
  }): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/email', data);
    return res.data;
  },

  analyzeQr: async (data: { image_base64?: string; decoded_payload?: string }): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/qr', data);
    return res.data;
  },

  analyzeWebpage: async (url: string, html_content?: string): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/webpage', { url, html_content });
    return res.data;
  },

  analyzeSocial: async (text: string, platform?: string): Promise<AnalysisResponse> => {
    const res = await apiClient.post<AnalysisResponse>('/analyze/social', { text, platform });
    return res.data;
  },

  // History & Samples
  getHistory: async (): Promise<{ analyses: AnalysisResponse[]; total: number }> => {
    const res = await apiClient.get('/history');
    return res.data;
  },

  getSamples: async (): Promise<{ samples: SamplePreset[] }> => {
    const res = await apiClient.get('/samples');
    return res.data;
  },

  // Submit threat report
  submitReport: async (data: {
    analysis_id?: string;
    target: string;
    threat_category: string;
    user_comments?: string;
  }) => {
    const res = await apiClient.post('/reports', data);
    return res.data;
  },
};

