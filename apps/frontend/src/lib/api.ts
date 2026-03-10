/*
SOC-CyBe Security Platform
Module: Frontend API Client

Purpose:
This file centralizes browser-side communication with the SOC-CyBe backend.
It keeps authentication headers, JSON parsing, and streaming behavior in one
place so the dashboard can focus on analyst workflows instead of transport code.

Security Notes:
- All state-changing UI actions flow through authenticated API requests.
- Keeping request logic here reduces the chance of one screen forgetting to
  send the bearer token or mishandling API errors.
- The SSE stream uses `fetch` instead of `EventSource` so the dashboard can
  attach the same JWT used by the rest of the platform.
*/

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type RequestOptions = RequestInit & {
  token?: string | null;
};

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");

  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (options.token) {
    headers.set("Authorization", `Bearer ${options.token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let detail = response.statusText || "Request failed";
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {
      /* Some endpoints may fail before JSON serialization. In that case the
         status text is still more useful than hiding the error entirely. */
    }
    throw new ApiError(detail, response.status);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export interface LoginPayload {
  email: string;
  password: string;
  ip_address: string;
  device_id: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface AuthenticatedUser {
  user_id: string;
  tenant_id: string | null;
  email: string;
  role: string;
  risk_score: number;
  device_trust: number;
  permissions: string[];
  session_id: string;
  session_status: string;
  zero_trust_decision: string;
  request_risk_score: number;
}

export interface AlertItem {
  id: string;
  severity: string;
  title: string;
  source: string;
  timestamp?: string;
  status: string;
}

export interface IncidentItem {
  id: string;
  title: string;
  severity: string;
  owner: string;
  status: string;
  response_stage: string;
}

export interface ThreatEventItem {
  id: string;
  event_type: string;
  severity: string;
  source: string;
  created_at: string;
  summary: string;
}

export interface AIFindingItem {
  id: string;
  event_id: string | null;
  anomaly_type: string;
  confidence_score: number;
  risk_score: number;
  severity: string;
  recommended_action: string;
  device_id: string | null;
  created_at: string;
}

export interface DetectionRuleItem {
  id: string;
  rule_name: string;
  severity_level: string;
  response_action: string;
  tactic: string | null;
  technique: string | null;
  mitre_technique_id: string | null;
  is_active: boolean;
}

export interface PlaybookItem {
  id: string;
  name: string;
  trigger_event: string;
  steps: Array<Record<string, unknown>>;
  requires_approval: boolean;
  is_active: boolean;
}

export interface CaseItem {
  id: string;
  incident_reference: string | null;
  assigned_analyst: string | null;
  investigation_notes: string;
  evidence_files: string[];
  status: string;
  resolution_summary: string | null;
  updated_at: string;
}

export interface SessionItem {
  session_id: string;
  user_id: string;
  ip_address: string;
  device_id: string | null;
  status: string;
  last_seen: string;
}

export interface DeviceItem {
  id: string;
  name?: string;
  type?: string;
  location?: string;
  risk?: number;
  device_id?: string;
  device_type?: string;
  risk_score?: number;
}

export interface PostureItem {
  id: string;
  environment_name: string;
  patch_status: number;
  vulnerable_software: number;
  inactive_security_controls: number;
  unsecured_services: number;
  posture_score: number;
  created_at: string;
}

export interface SimulationItem {
  id: string;
  scenario_name: string;
  scenario_type: string;
  mode: string;
  intensity_level: string;
  duration_minutes: number;
  target_user: string | null;
  target_device: string | null;
  training_mode: boolean;
  scheduled_for: string | null;
  started_at: string | null;
  completed_at: string | null;
  status: string;
  safety_status: string;
  safety_notes: string;
  expected_detection: string;
  scenario_config: Record<string, unknown>;
  detection_summary: Record<string, unknown>;
  timeline: Array<Record<string, unknown>>;
}

export interface ThreatHuntResultItem {
  event_id: string;
  event_type: string;
  severity: string;
  source: string;
  username: string | null;
  ip_address: string | null;
  device_id: string | null;
  created_at: string;
  risk_score: number;
  summary: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
  intel_matches: string[];
}

export interface ThreatHuntTimelineItem {
  timestamp: string;
  event_id: string;
  event_type: string;
  description: string;
  source: string;
}

export interface ThreatHuntSearchResponse {
  query_summary: string;
  total_results: number;
  results: ThreatHuntResultItem[];
  timeline: ThreatHuntTimelineItem[];
  behavioral_patterns: string[];
  ai_suggestions: string[];
}

export interface SavedThreatHuntItem {
  id: string;
  name: string;
  description: string | null;
  filters: Record<string, unknown>;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface ThreatHuntReportItem {
  id: string;
  title: string;
  summary: string;
  events_analyzed: number;
  identified_threats: string[];
  recommended_mitigations: string[];
  export_format: string;
  created_at: string;
}

export interface AttackGraphNode {
  id: string;
  node_type: string;
  label: string;
  risk_score: number;
  risk_level: string;
  color: string;
  intel_match: boolean;
  alert_count: number;
  details: Record<string, unknown>;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  action: string;
  timestamp: string;
  source_system: string;
  destination_system: string;
  severity: string;
  details: Record<string, unknown>;
}

export interface AttackGraphTimelineItem {
  timestamp: string;
  event_id: string;
  action: string;
  actor: string | null;
  target: string | null;
  severity: string;
  description: string;
}

export interface AttackGraphPayload {
  incident_id: string | null;
  active_attack_paths: number;
  compromised_devices: number;
  high_risk_users: number;
  ongoing_incidents: number;
  ai_attack_path_suggestions: string[];
  lateral_movement_paths: string[][];
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  timeline: AttackGraphTimelineItem[];
}

export interface DashboardPayload {
  metrics?: Array<{ label: string; value: string | number; delta: string }>;
  alerts?: AlertItem[];
  incidents?: IncidentItem[];
}

export interface InvestigationActivity {
  id: string;
  activity_type: string;
  notes: string;
  created_at: string;
}

export interface StreamPayload {
  alerts: AlertItem[];
  ai_findings: AIFindingItem[];
  attack_graph?: AttackGraphPayload;
}

export async function login(payload: LoginPayload): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getMe(token: string): Promise<AuthenticatedUser> {
  return request<AuthenticatedUser>("/auth/me", { token });
}

export async function getDashboard(token: string): Promise<DashboardPayload> {
  return request<DashboardPayload>("/dashboard", { token });
}

export async function getAlerts(token: string): Promise<{ items: AlertItem[] }> {
  return request<{ items: AlertItem[] }>("/alerts", { token });
}

export async function getIncidents(token: string): Promise<IncidentItem[]> {
  return request<IncidentItem[]>("/incidents", { token });
}

export async function getThreatEvents(token: string): Promise<ThreatEventItem[]> {
  return request<ThreatEventItem[]>("/threats/events", { token });
}

export async function getAIFindings(token: string): Promise<AIFindingItem[]> {
  return request<AIFindingItem[]>("/ai/findings", { token });
}

export async function getRules(token: string): Promise<DetectionRuleItem[]> {
  return request<DetectionRuleItem[]>("/rules", { token });
}

export async function getPlaybooks(token: string): Promise<PlaybookItem[]> {
  return request<PlaybookItem[]>("/playbooks", { token });
}

export async function getCases(token: string): Promise<CaseItem[]> {
  return request<CaseItem[]>("/cases", { token });
}

export async function getPosture(token: string): Promise<PostureItem[]> {
  return request<PostureItem[]>("/posture", { token });
}

export async function getSessions(token: string): Promise<SessionItem[]> {
  return request<SessionItem[]>("/sessions", { token });
}

export async function getDevices(token: string): Promise<DeviceItem[]> {
  return request<DeviceItem[]>("/devices", { token });
}

export async function getGatewayStatus(token: string): Promise<Record<string, string>> {
  return request<Record<string, string>>("/gateway/status", { token });
}

export async function getSimulations(token: string): Promise<SimulationItem[]> {
  return request<SimulationItem[]>("/simulations", { token });
}

export async function getAttackGraph(token: string, incidentId?: string | null) {
  const suffix = incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : "";
  return request<AttackGraphPayload>(`/attack-graph${suffix}`, { token });
}

export async function searchThreatHunts(
  token: string,
  payload: {
    username?: string;
    ip_address?: string;
    device_id?: string;
    event_type?: string;
    min_risk_score?: number;
    query_text?: string;
    limit?: number;
  },
) {
  return request<ThreatHuntSearchResponse>("/hunting/search", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function getSavedThreatHunts(token: string) {
  return request<SavedThreatHuntItem[]>("/hunting/saved-queries", { token });
}

export async function saveThreatHunt(
  token: string,
  payload: {
    name: string;
    description?: string;
    filters: Record<string, unknown>;
    notes?: string;
  },
) {
  return request<SavedThreatHuntItem>("/hunting/saved-queries", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function getThreatHuntReports(token: string) {
  return request<ThreatHuntReportItem[]>("/hunting/reports", { token });
}

export async function createThreatHuntReport(
  token: string,
  payload: {
    title: string;
    summary: string;
    events_analyzed: number;
    identified_threats: string[];
    recommended_mitigations: string[];
    query_id?: string | null;
    export_format?: "json" | "markdown";
  },
) {
  return request<ThreatHuntReportItem>("/hunting/reports", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function promoteThreatHunt(
  token: string,
  payload: {
    title: string;
    description: string;
    severity: "Low" | "Medium" | "High" | "Critical";
    affected_asset: string;
    evidence_event_ids: string[];
  },
) {
  return request<{ alert_id: string; incident_id: string; case_id: string; status: string }>("/hunting/promote", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function getIncidentActivities(token: string, incidentId: string): Promise<InvestigationActivity[]> {
  return request<InvestigationActivity[]>(`/incidents/${incidentId}/activities`, { token });
}

export async function createIncident(
  token: string,
  payload: {
    title: string;
    description: string;
    severity: "Low" | "Medium" | "High" | "Critical";
    affected_asset: string;
  },
) {
  return request("/incidents", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function createCase(
  token: string,
  payload: {
    incident_reference?: string | null;
    investigation_notes: string;
    evidence_files?: string[];
  },
) {
  return request("/cases", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function createRule(
  token: string,
  payload: {
    rule_name: string;
    event_conditions: Record<string, unknown>;
    severity_level: "Low" | "Medium" | "High" | "Critical";
    response_action: string;
    tactic?: string;
    technique?: string;
    mitre_technique_id?: string;
  },
) {
  return request("/rules", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function toggleRule(token: string, ruleId: string) {
  return request(`/rules/${ruleId}/toggle`, {
    method: "PATCH",
    token,
  });
}

export async function testRule(token: string, ruleId: string, eventPayload: Record<string, unknown>) {
  return request<{ matched: boolean; severity: string | null; response_action: string | null }>(`/rules/${ruleId}/test`, {
    method: "POST",
    token,
    body: JSON.stringify({ event_payload: eventPayload }),
  });
}

export async function executePlaybook(token: string, playbookId: string) {
  return request<{ execution_mode: string; executed_steps: string[] }>(`/playbooks/${playbookId}/execute`, {
    method: "POST",
    token,
  });
}

export async function trainAI(token: string, lookback_hours: number) {
  return request<{ trained: boolean; sample_count: number; model_version: string; lookback_hours: number }>("/ai/train", {
    method: "POST",
    token,
    body: JSON.stringify({ lookback_hours }),
  });
}

export async function createSimulation(
  token: string,
  payload: {
    scenario_name: string;
    scenario_type:
      | "brute_force"
      | "suspicious_login_location"
      | "privilege_escalation"
      | "malicious_file_execution"
      | "data_exfiltration";
    mode: "manual" | "scheduled" | "randomized";
    target_user?: string;
    target_device?: string;
    intensity_level: "Low" | "Medium" | "High";
    duration_minutes: number;
    training_mode: boolean;
    expected_detection: string;
    scheduled_for?: string | null;
  },
) {
  return request<SimulationItem>("/simulations", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
  });
}

export async function startSimulation(token: string, simulationId: string) {
  return request<{ simulation_id: string; status: string; message: string }>(`/simulations/${simulationId}/start`, {
    method: "POST",
    token,
  });
}

export async function stopSimulation(token: string, simulationId: string) {
  return request<{ simulation_id: string; status: string; message: string }>(`/simulations/${simulationId}/stop`, {
    method: "POST",
    token,
  });
}

export async function connectAlertStream(
  token: string,
  handlers: {
    onMessage: (payload: StreamPayload) => void;
    onError?: (error: Error) => void;
    signal?: AbortSignal;
  },
) {
  const response = await fetch(`${API_BASE}/stream/alerts`, {
    method: "GET",
    headers: {
      Accept: "text/event-stream",
      Authorization: `Bearer ${token}`,
    },
    signal: handlers.signal,
    cache: "no-store",
  });

  if (!response.ok || !response.body) {
    throw new ApiError("Unable to open real-time alert stream", response.status);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }

      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.split("\n\n");
      buffer = frames.pop() ?? "";

      for (const frame of frames) {
        const line = frame
          .split("\n")
          .find((entry) => entry.startsWith("data: "));

        if (!line) {
          continue;
        }

        try {
          handlers.onMessage(JSON.parse(line.slice(6)) as StreamPayload);
        } catch (error) {
          handlers.onError?.(error instanceof Error ? error : new Error("Invalid stream payload"));
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}
