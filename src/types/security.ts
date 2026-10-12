export type RiskLevel = 'Safe' | 'Moderate Risk' | 'High Risk' | 'Critical Risk';

export interface IdentifiedFlaw {
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  threatMechanism: string;
  exploitationScenario: string;
  affectedCodeOrInput: string;
  impact: string;
}

export interface OwaspRecommendation {
  category: string;
  guideline: string;
  rationale: string;
}

export interface AuditResult {
  riskLevel: RiskLevel;
  cvssScore: number;
  cweId: string;
  owaspCategory: string;
  executiveSummary: string;
  identifiedFlaws: IdentifiedFlaw[];
  patchedCode: string;
  patchLanguage: string;
  patchExplanation: string;
  owaspRecommendations: OwaspRecommendation[];
  automatedDefenseRule?: string;
}

export interface AuditHistoryItem {
  id: string;
  timestamp: number;
  inputType: 'code' | 'http' | 'log';
  targetEnvironment: string;
  title: string;
  snippetPreview: string;
  inputContent: string;
  result: AuditResult;
}

export interface PresetSample {
  id: string;
  title: string;
  category: string;
  inputType: 'code' | 'http' | 'log';
  targetEnvironment: string;
  description: string;
  badge: string;
  code: string;
}
