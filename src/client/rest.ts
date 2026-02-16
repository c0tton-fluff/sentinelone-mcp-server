import { getConfig } from "../config.js";
import { sanitizeError } from "../utils.js";
import type {
  PaginatedResponse,
  Threat,
  Agent,
  DVQueryResponse,
  DVQueryStatus,
  DVEvent,
  MitigationAction,
} from "./types.js";

const TIMEOUT_MS = 30000;

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const config = getConfig();
  const url = `${config.apiBase}/web/api/v2.1${endpoint}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Authorization: `ApiToken ${config.apiKey}`,
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `HTTP ${response.status}: ${response.statusText} - ${errorBody}`
      );
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`Request timeout after ${TIMEOUT_MS}ms`);
    }
    throw new Error(sanitizeError(error));
  } finally {
    clearTimeout(timeoutId);
  }
}

// Threats API
export async function listThreats(params?: {
  limit?: number;
  cursor?: string;
  siteIds?: string[];
  groupIds?: string[];
  resolved?: boolean;
  mitigationStatuses?: string[];
  classifications?: string[];
  analystVerdicts?: string[];
  computerNameContains?: string;
  threatNameContains?: string;
}): Promise<PaginatedResponse<Threat>> {
  const searchParams = new URLSearchParams();

  if (params?.limit) searchParams.set("limit", String(params.limit));
  if (params?.cursor) searchParams.set("cursor", params.cursor);
  if (params?.siteIds?.length)
    searchParams.set("siteIds", params.siteIds.join(","));
  if (params?.groupIds?.length)
    searchParams.set("groupIds", params.groupIds.join(","));
  if (params?.resolved !== undefined)
    searchParams.set("resolved", String(params.resolved));
  if (params?.mitigationStatuses?.length)
    searchParams.set("mitigationStatuses", params.mitigationStatuses.join(","));
  if (params?.classifications?.length)
    searchParams.set("classifications", params.classifications.join(","));
  if (params?.analystVerdicts?.length)
    searchParams.set("analystVerdicts", params.analystVerdicts.join(","));
  if (params?.computerNameContains)
    searchParams.set("computerName__contains", params.computerNameContains);
  if (params?.threatNameContains)
    searchParams.set("threatDetails__contains", params.threatNameContains);

  const query = searchParams.toString();
  return request<PaginatedResponse<Threat>>(
    `/threats${query ? `?${query}` : ""}`
  );
}

export async function getThreat(
  threatId: string
): Promise<PaginatedResponse<Threat>> {
  const searchParams = new URLSearchParams({ ids: threatId });
  return request<PaginatedResponse<Threat>>(`/threats?${searchParams.toString()}`);
}

export async function mitigateThreat(
  threatId: string,
  action: MitigationAction
): Promise<{ data: { affected: number } }> {
  return request<{ data: { affected: number } }>(
    `/threats/mitigate/${action}`,
    {
      method: "POST",
      body: JSON.stringify({
        filter: { ids: [threatId] },
      }),
    }
  );
}

// Agents API
export async function listAgents(params?: {
  limit?: number;
  cursor?: string;
  siteIds?: string[];
  groupIds?: string[];
  computerNameContains?: string;
  osTypes?: string[];
  isActive?: boolean;
  isInfected?: boolean;
  networkStatuses?: string[];
}): Promise<PaginatedResponse<Agent>> {
  const searchParams = new URLSearchParams();

  if (params?.limit) searchParams.set("limit", String(params.limit));
  if (params?.cursor) searchParams.set("cursor", params.cursor);
  if (params?.siteIds?.length)
    searchParams.set("siteIds", params.siteIds.join(","));
  if (params?.groupIds?.length)
    searchParams.set("groupIds", params.groupIds.join(","));
  if (params?.computerNameContains)
    searchParams.set("computerName__contains", params.computerNameContains);
  if (params?.osTypes?.length)
    searchParams.set("osTypes", params.osTypes.join(","));
  if (params?.isActive !== undefined)
    searchParams.set("isActive", String(params.isActive));
  if (params?.isInfected !== undefined)
    searchParams.set("isInfected", String(params.isInfected));
  if (params?.networkStatuses?.length)
    searchParams.set("networkStatuses", params.networkStatuses.join(","));

  const query = searchParams.toString();
  return request<PaginatedResponse<Agent>>(`/agents${query ? `?${query}` : ""}`);
}

export async function getAgent(
  agentId: string
): Promise<PaginatedResponse<Agent>> {
  const searchParams = new URLSearchParams({ ids: agentId });
  return request<PaginatedResponse<Agent>>(`/agents?${searchParams.toString()}`);
}

export async function isolateAgent(
  agentId: string
): Promise<{ data: { affected: number } }> {
  return request<{ data: { affected: number } }>(
    "/agents/actions/disconnect",
    {
      method: "POST",
      body: JSON.stringify({
        filter: { ids: [agentId] },
      }),
    }
  );
}

export async function reconnectAgent(
  agentId: string
): Promise<{ data: { affected: number } }> {
  return request<{ data: { affected: number } }>("/agents/actions/connect", {
    method: "POST",
    body: JSON.stringify({
      filter: { ids: [agentId] },
    }),
  });
}

// Deep Visibility API
export async function createDVQuery(params: {
  query: string;
  fromDate: string;
  toDate: string;
  siteIds?: string[];
  groupIds?: string[];
  accountIds?: string[];
}): Promise<DVQueryResponse> {
  const response = await request<{ data: DVQueryResponse }>(
    "/dv/init-query",
    {
      method: "POST",
      body: JSON.stringify({
        query: params.query,
        fromDate: params.fromDate,
        toDate: params.toDate,
        ...(params.siteIds?.length && { siteIds: params.siteIds }),
        ...(params.groupIds?.length && { groupIds: params.groupIds }),
        ...(params.accountIds?.length && { accountIds: params.accountIds }),
      }),
    }
  );
  return response.data;
}

export async function getDVQueryStatus(
  queryId: string
): Promise<DVQueryStatus> {
  const response = await request<{ data: DVQueryStatus }>(
    `/dv/query-status?${new URLSearchParams({ queryId }).toString()}`
  );
  return response.data;
}

export async function getDVEvents(params: {
  queryId: string;
  limit?: number;
  cursor?: string;
}): Promise<PaginatedResponse<DVEvent>> {
  const searchParams = new URLSearchParams();
  searchParams.set("queryId", params.queryId);
  if (params.limit) searchParams.set("limit", String(params.limit));
  if (params.cursor) searchParams.set("cursor", params.cursor);

  return request<PaginatedResponse<DVEvent>>(
    `/dv/events?${searchParams.toString()}`
  );
}
