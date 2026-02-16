// Common pagination response
export interface PaginatedResponse<T> {
  data: T[];
  pagination?: {
    nextCursor?: string;
    totalItems?: number;
  };
}

// Threat types
export interface Threat {
  id: string;
  agentId: string;
  agentComputerName: string;
  agentOsType: string;
  classification: string;
  classificationSource: string;
  confidenceLevel: string;
  createdAt: string;
  description: string;
  fileContentHash: string;
  filePath: string;
  initiatedBy: string;
  initiatedByDescription: string;
  mitigationStatus: string;
  threatName: string;
  storylineId: string;
  threatInfo?: {
    sha1?: string;
    sha256?: string;
    md5?: string;
    filePath?: string;
    fileSize?: number;
  };
}

export type MitigationAction =
  | "kill"
  | "quarantine"
  | "remediate"
  | "rollback-remediation";

// Agent types
export interface Agent {
  id: string;
  uuid: string;
  computerName: string;
  domain: string;
  siteName: string;
  groupName: string;
  osName: string;
  osType: string;
  agentVersion: string;
  isActive: boolean;
  isDecommissioned: boolean;
  infected: boolean;
  networkStatus: string;
  lastActiveDate: string;
  externalIp: string;
  networkInterfaces: Array<{
    inet: string[];
    physical: string;
    name: string;
  }>;
}

// Deep Visibility types
export interface DVQueryResponse {
  queryId: string;
  status: string;
}

export interface DVEvent {
  id: string;
  eventType: string;
  eventTime: string;
  agentId: string;
  agentName: string;
  processName: string;
  processImagePath?: string;
  processCommandLine?: string;
  processUser?: string;
  parentProcessName?: string;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  filePath?: string;
  sha1?: string;
  sha256?: string;
  registryPath?: string;
  registryValue?: string;
  dnsRequest?: string;
  url?: string;
}

export interface DVQueryStatus {
  queryId: string;
  status: "RUNNING" | "FINISHED" | "FAILED" | "CANCELED";
  progressStatus?: number;
  responseError?: string;
}

// GraphQL Alert types
export interface Alert {
  alertId: string;
  severity: string;
  analystVerdict: string;
  incidentStatus: string;
  threatName: string;
  classification: string;
  storylineId: string;
  agentId: string;
  agentName: string;
  siteName: string;
  createdAt: string;
  updatedAt: string;
}

// API Error response
export interface ApiError {
  errors?: Array<{
    code: number;
    detail: string;
    title: string;
  }>;
}
