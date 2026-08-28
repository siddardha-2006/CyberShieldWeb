export type InputType = 'url' | 'message' | 'email' | 'qr' | 'webpage' | 'social';

export type Severity = 'safe' | 'suspicious' | 'high_risk' | 'critical';

export type SafeAction = 'ALLOW' | 'WARN' | 'DO_NOT_INTERACT' | 'REPORT';

export interface EvidenceItem {
  engine: string;
  code: string;
  title: string;
  description: string;
  weight: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  metadata?: Record<string, any>;
}

export interface EngineResult {
  engine: 'rules' | 'nlp' | 'threat_intelligence' | 'behavior';
  status: 'completed' | 'timeout' | 'error' | 'unavailable' | 'not_applicable';
  score: number;
  confidence: number;
  evidence: EvidenceItem[];
  classifications?: Record<string, number>;
  observations?: Record<string, any>;
  sources?: string[];
  latency_ms: number;
  error_message?: string;
}

export interface RiskAssessment {
  risk_score: number;
  confidence: number;
  severity: Severity;
  category: string;
  secondary_categories: string[];
  recommended_action: SafeAction;
  action_details: string;
}

export interface ExplainabilityResponse {
  summary: string;
  key_reasons: string[];
  evidence_breakdown: EvidenceItem[];
  safe_steps: string[];
}

export interface AnalysisResponse {
  analysis_id: string;
  input_type: InputType;
  indicator_hmac: string;
  created_at: string;
  assessment: RiskAssessment;
  engines: {
    rules?: EngineResult;
    nlp?: EngineResult;
    threat_intelligence?: EngineResult;
    behavior?: EngineResult;
  };
  explainability: ExplainabilityResponse;
  language_info?: {
    is_translated: boolean;
    detected_language: string;
    original_text: string;
    translated_text: string;
  };
  duration_ms: number;
}

export interface SamplePreset {
  id: string;
  title: string;
  type: InputType;
  severity_expected: Severity;
  payload: Record<string, any>;
}

