"use client";

/*
SOC-CyBe Security Platform
Module: Interactive Dashboard Shell

Purpose:
This component turns the SOC-CyBe frontend into a working analyst console.
It handles authentication, data loading, real-time alert updates, incident
creation, case management, playbook execution, and detection rule operations.

Architecture Notes:
- The component talks to the FastAPI backend through `src/lib/api.ts`.
- Data is loaded as a tenant-scoped bundle so the dashboard reflects the
  authenticated organization's security state.
- Live alerts and AI findings are streamed over SSE-compatible fetch requests.

Security Notes:
- UI actions respect the RBAC model exposed by the backend. The interface hides
  or disables actions that the current role should not perform.
- Forms perform client-side validation for usability, but the backend remains
  the source of truth for authorization and input validation.
- Sensitive actions are executed through authenticated APIs, which means they
  are also captured by the platform's audit logging layer.
*/

import { startTransition, useCallback, useEffect, useState, type FormEvent } from "react";

import {
  ApiError,
  type AttackGraphEdge,
  type AttackGraphNode,
  type AttackGraphPayload,
  type AIFindingItem,
  type AlertItem,
  type AuthenticatedUser,
  type CaseItem,
  connectAlertStream,
  createCase,
  createIncident,
  createRule,
  createSimulation,
  executePlaybook,
  getAttackGraph,
  getAIFindings,
  getAlerts,
  getCases,
  getDashboard,
  getDevices,
  getGatewayStatus,
  getIncidentActivities,
  getIncidents,
  getMe,
  getPlaybooks,
  getPosture,
  getRules,
  getSessions,
  getSimulations,
  getThreatEvents,
  login,
  startSimulation,
  stopSimulation,
  testRule,
  toggleRule,
  trainAI,
  type DetectionRuleItem,
  type DeviceItem,
  type IncidentItem,
  type InvestigationActivity,
  type PlaybookItem,
  type PostureItem,
  type SessionItem,
  type SimulationItem,
  type ThreatEventItem,
} from "@/lib/api";

type DashboardState = {
  dashboardMetrics: Array<{ label: string; value: string | number; delta: string }>;
  alerts: AlertItem[];
  incidents: IncidentItem[];
  threatEvents: ThreatEventItem[];
  aiFindings: AIFindingItem[];
  rules: DetectionRuleItem[];
  playbooks: PlaybookItem[];
  cases: CaseItem[];
  sessions: SessionItem[];
  devices: DeviceItem[];
  posture: PostureItem[];
  simulations: SimulationItem[];
  attackGraph: AttackGraphPayload | null;
  gatewayStatus: Record<string, string>;
};

const EMPTY_STATE: DashboardState = {
  dashboardMetrics: [],
  alerts: [],
  incidents: [],
  threatEvents: [],
  aiFindings: [],
  rules: [],
  playbooks: [],
  cases: [],
  sessions: [],
  devices: [],
  posture: [],
  simulations: [],
  attackGraph: null,
  gatewayStatus: {},
};

function severityTone(severity: string) {
  if (severity === "Critical") return "critical";
  if (severity === "High") return "high";
  if (severity === "Medium" || severity === "Moderate") return "medium";
  return "low";
}

function formatTime(value?: string) {
  if (!value) {
    return "pending";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function safeJsonParse(value: string) {
  return JSON.parse(value) as Record<string, unknown>;
}

function passwordIsStrong(password: string) {
  return password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password);
}

export function DashboardShell() {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthenticatedUser | null>(null);
  const [data, setData] = useState<DashboardState>(EMPTY_STATE);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);
  const [incidentActivities, setIncidentActivities] = useState<InvestigationActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [streamState, setStreamState] = useState("offline");
  const [statusMessage, setStatusMessage] = useState("Authenticate to start live SOC monitoring.");
  const [loginForm, setLoginForm] = useState({
    email: "admin@soc-cybe.io",
    password: "AdminZeroTrust!2026",
    ipAddress: "127.0.0.1",
    deviceId: "ui-console-01",
  });
  const [ruleForm, setRuleForm] = useState({
    rule_name: "",
    severity_level: "High",
    response_action: "Escalate to analyst review",
    tactic: "Credential Access",
    technique: "Brute Force",
    mitre_technique_id: "T1110",
    event_conditions: '{ "event_type": "failed_login", "count": 10 }',
  });
  const [ruleTestPayload, setRuleTestPayload] = useState('{ "event_type": "failed_login", "count": 12 }');
  const [ruleTestResult, setRuleTestResult] = useState<string>("");
  const [caseNotes, setCaseNotes] = useState("Initial investigation opened from live alert review.");
  const [simulationForm, setSimulationForm] = useState({
    scenario_name: "Lab Credential Attack Drill",
    scenario_type: "brute_force",
    mode: "manual",
    target_user: "analyst.training@soc-cybe.lab",
    target_device: "lab-endpoint-01",
    intensity_level: "Medium",
    duration_minutes: 5,
    training_mode: true,
    expected_detection: "SOC-CyBe should raise a brute-force alert and create an incident for analyst review.",
  });
  const [selectedSimulation, setSelectedSimulation] = useState<SimulationItem | null>(null);
  const [selectedGraphNode, setSelectedGraphNode] = useState<AttackGraphNode | null>(null);
  const [selectedGraphEdge, setSelectedGraphEdge] = useState<AttackGraphEdge | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  const canManageRules = user?.permissions.includes("users:manage") ?? false;
  const canRespond = user?.permissions.includes("incidents:write") ?? false;
  const canReadLogs = user?.permissions.includes("logs:read") ?? false;

  const openAlerts = data.alerts.filter((item) => item.status !== "Resolved").length;
  const criticalFindings = data.aiFindings.filter((item) => item.severity === "Critical").length;
  const openIncidents = data.incidents.filter((item) => item.status !== "Closed").length;
  const averageRisk =
    data.aiFindings.length > 0
      ? Math.round(data.aiFindings.reduce((sum, item) => sum + item.risk_score, 0) / data.aiFindings.length)
      : user?.risk_score ?? 0;
  const topMetrics = [
    { label: "Active Alerts", value: openAlerts, delta: streamState },
    { label: "Critical AI Findings", value: criticalFindings, delta: "behavioral model" },
    { label: "Open Incidents", value: openIncidents, delta: user?.zero_trust_decision ?? "allow" },
    { label: "Average Risk Score", value: averageRisk, delta: user ? user.role : "guest" },
  ];

  const riskHotlist = [...data.aiFindings]
    .sort((left, right) => right.risk_score - left.risk_score)
    .slice(0, 4);

  const titleTokens = selectedAlert?.title.toLowerCase().split(/\s+/) ?? [];
  const threatMatches =
    selectedAlert === null
      ? []
      : data.threatEvents.filter((event) =>
          titleTokens.some((tokenPart) => tokenPart.length > 3 && event.summary.toLowerCase().includes(tokenPart)),
        );
  const relatedThreatEvents = (
    selectedAlert === null ? data.threatEvents : threatMatches.length > 0 ? threatMatches : data.threatEvents
  ).slice(0, 5);

  const applyStreamUpdate = useCallback((payload: { alerts: AlertItem[]; ai_findings: AIFindingItem[]; attack_graph?: AttackGraphPayload }) => {
    startTransition(() => {
      setData((current) => ({
        ...current,
        alerts: payload.alerts.length > 0 ? payload.alerts : current.alerts,
        aiFindings: payload.ai_findings.length > 0 ? payload.ai_findings : current.aiFindings,
        attackGraph: payload.attack_graph ?? current.attackGraph,
      }));
      setStreamState("streaming");
      setStatusMessage("Real-time threat stream connected.");
    });
  }, []);

  useEffect(() => {
    const storedToken = window.sessionStorage.getItem("soc_cybe_token");
    if (storedToken) {
      setToken(storedToken);
    } else {
      setLoading(false);
    }
  }, []);

  async function loadDashboard(activeToken: string) {
    const [
      meResponse,
      dashboardResponse,
      alertsResponse,
      incidentsResponse,
      threatEventsResponse,
      aiFindingsResponse,
      rulesResponse,
      playbooksResponse,
      casesResponse,
      sessionsResponse,
      devicesResponse,
      postureResponse,
      simulationsResponse,
      attackGraphResponse,
      gatewayStatusResponse,
    ] = await Promise.all([
      getMe(activeToken),
      getDashboard(activeToken),
      getAlerts(activeToken),
      getIncidents(activeToken),
      getThreatEvents(activeToken),
      getAIFindings(activeToken),
      getRules(activeToken),
      getPlaybooks(activeToken),
      getCases(activeToken),
      getSessions(activeToken),
      getDevices(activeToken),
      getPosture(activeToken),
      getSimulations(activeToken),
      getAttackGraph(activeToken, selectedIncident?.id ?? null),
      getGatewayStatus(activeToken),
    ]);

    setUser(meResponse);
    setData({
      dashboardMetrics: dashboardResponse.metrics ?? [],
      alerts: alertsResponse.items ?? [],
      incidents: incidentsResponse,
      threatEvents: threatEventsResponse,
      aiFindings: aiFindingsResponse,
      rules: rulesResponse,
      playbooks: playbooksResponse,
      cases: casesResponse,
      sessions: sessionsResponse,
      devices: devicesResponse,
      posture: postureResponse,
      simulations: simulationsResponse,
      attackGraph: attackGraphResponse,
      gatewayStatus: gatewayStatusResponse,
    });
    setSelectedAlert((current) => current ?? alertsResponse.items?.[0] ?? null);
    setSelectedIncident((current) => current ?? incidentsResponse[0] ?? null);
    setSelectedSimulation((current) =>
      current ? simulationsResponse.find((item) => item.id === current.id) ?? simulationsResponse[0] ?? null : simulationsResponse[0] ?? null,
    );
    setSelectedGraphNode((current) =>
      current ? attackGraphResponse.nodes.find((item) => item.id === current.id) ?? attackGraphResponse.nodes[0] ?? null : attackGraphResponse.nodes[0] ?? null,
    );
    setSelectedGraphEdge((current) =>
      current ? attackGraphResponse.edges.find((item) => item.id === current.id) ?? attackGraphResponse.edges[0] ?? null : attackGraphResponse.edges[0] ?? null,
    );
    setStatusMessage("SOC telemetry loaded.");
  }

  useEffect(() => {
    if (!token) {
      return;
    }

    let cancelled = false;
    setLoading(true);

    loadDashboard(token)
      .catch((error) => {
        const message = error instanceof ApiError ? error.message : "Unable to load dashboard.";
        setStatusMessage(message);
        if (error instanceof ApiError && error.status === 401) {
          window.sessionStorage.removeItem("soc_cybe_token");
          setToken(null);
          setUser(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (!token) {
      return;
    }

    const controller = new AbortController();
    setStreamState("connecting");

    connectAlertStream(token, {
      signal: controller.signal,
      onMessage: applyStreamUpdate,
      onError: () => setStreamState("degraded"),
    }).catch((error) => {
      if (!controller.signal.aborted) {
        setStreamState("degraded");
        setStatusMessage(error instanceof Error ? error.message : "Alert stream unavailable.");
      }
    });

    return () => controller.abort();
  }, [applyStreamUpdate, token]);

  useEffect(() => {
    if (!token || !selectedIncident) {
      setIncidentActivities([]);
      return;
    }

    getIncidentActivities(token, selectedIncident.id)
      .then(setIncidentActivities)
      .catch(() => setIncidentActivities([]));
  }, [selectedIncident, token]);

  useEffect(() => {
    if (!token) {
      return;
    }
    getAttackGraph(token, selectedIncident?.id ?? null)
      .then((graph) => {
        setData((current) => ({ ...current, attackGraph: graph }));
        setSelectedGraphNode((current) =>
          current ? graph.nodes.find((item) => item.id === current.id) ?? graph.nodes[0] ?? null : graph.nodes[0] ?? null,
        );
        setSelectedGraphEdge((current) =>
          current ? graph.edges.find((item) => item.id === current.id) ?? graph.edges[0] ?? null : graph.edges[0] ?? null,
        );
      })
      .catch(() => undefined);
  }, [selectedIncident, token]);

  async function handleLoginSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!loginForm.email.includes("@")) {
      setStatusMessage("Enter a valid analyst email address.");
      return;
    }
    if (!passwordIsStrong(loginForm.password)) {
      setStatusMessage("Password must be at least 12 characters and include an uppercase letter and a number.");
      return;
    }

    setBusy(true);
    try {
      const response = await login({
        email: loginForm.email,
        password: loginForm.password,
        ip_address: loginForm.ipAddress,
        device_id: loginForm.deviceId,
      });
      window.sessionStorage.setItem("soc_cybe_token", response.access_token);
      setToken(response.access_token);
      setStatusMessage("Authenticated. Establishing Zero Trust session.");
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  function handleLogout() {
    window.sessionStorage.removeItem("soc_cybe_token");
    setToken(null);
    setUser(null);
    setData(EMPTY_STATE);
    setSelectedAlert(null);
    setSelectedIncident(null);
    setStatusMessage("Session cleared.");
  }

  async function refreshAll() {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      await loadDashboard(token);
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Refresh failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateIncidentFromAlert() {
    if (!token || !selectedAlert) {
      return;
    }
    setBusy(true);
    try {
      await createIncident(token, {
        title: `Escalated: ${selectedAlert.title}`,
        description: `Escalated from alert ${selectedAlert.id} via dashboard workflow.`,
        severity: (selectedAlert.severity === "Moderate" ? "Medium" : selectedAlert.severity) as
          | "Low"
          | "Medium"
          | "High"
          | "Critical",
        affected_asset: selectedAlert.source,
      });
      setStatusMessage(`Incident created from alert ${selectedAlert.id}.`);
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to create incident.");
    } finally {
      setBusy(false);
    }
  }

  async function handleOpenCase() {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      await createCase(token, {
        incident_reference: selectedIncident?.id ?? null,
        investigation_notes: caseNotes,
        evidence_files: selectedAlert ? [selectedAlert.id] : [],
      });
      setStatusMessage("Investigation case created.");
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to create case.");
    } finally {
      setBusy(false);
    }
  }

  async function handleExecutePlaybook(playbookId: string) {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      const result = await executePlaybook(token, playbookId);
      setStatusMessage(`Playbook executed in ${result.execution_mode} mode: ${result.executed_steps.join(", ")}`);
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to execute playbook.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) {
      return;
    }

    let parsedConditions: Record<string, unknown>;
    try {
      parsedConditions = safeJsonParse(ruleForm.event_conditions);
    } catch {
      setStatusMessage("Detection rule conditions must be valid JSON.");
      return;
    }

    setBusy(true);
    try {
      await createRule(token, {
        rule_name: ruleForm.rule_name,
        severity_level: ruleForm.severity_level as "Low" | "Medium" | "High" | "Critical",
        response_action: ruleForm.response_action,
        tactic: ruleForm.tactic,
        technique: ruleForm.technique,
        mitre_technique_id: ruleForm.mitre_technique_id,
        event_conditions: parsedConditions,
      });
      setRuleForm((current) => ({ ...current, rule_name: "" }));
      setStatusMessage("Detection rule created.");
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to create detection rule.");
    } finally {
      setBusy(false);
    }
  }

  async function handleToggleRule(ruleId: string) {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      await toggleRule(token, ruleId);
      setStatusMessage("Detection rule state updated.");
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to update rule.");
    } finally {
      setBusy(false);
    }
  }

  async function handleTestRule(ruleId: string) {
    if (!token) {
      return;
    }

    let parsedPayload: Record<string, unknown>;
    try {
      parsedPayload = safeJsonParse(ruleTestPayload);
    } catch {
      setStatusMessage("Rule test payload must be valid JSON.");
      return;
    }

    setBusy(true);
    try {
      const result = await testRule(token, ruleId, parsedPayload);
      setRuleTestResult(
        result.matched
          ? `Matched. Severity ${result.severity}. Response ${result.response_action}.`
          : "No rule match for the supplied payload.",
      );
      setStatusMessage("Rule sandbox executed.");
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to test rule.");
    } finally {
      setBusy(false);
    }
  }

  async function handleTrainAI() {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      const result = await trainAI(token, 168);
      setStatusMessage(`AI model refreshed with ${result.sample_count} historical events.`);
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to train AI model.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateSimulation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) {
      return;
    }

    if (!simulationForm.scenario_name.trim()) {
      setStatusMessage("Simulation name is required.");
      return;
    }

    setBusy(true);
    try {
      const simulation = await createSimulation(token, {
        scenario_name: simulationForm.scenario_name,
        scenario_type: simulationForm.scenario_type as
          | "brute_force"
          | "suspicious_login_location"
          | "privilege_escalation"
          | "malicious_file_execution"
          | "data_exfiltration",
        mode: simulationForm.mode as "manual" | "scheduled" | "randomized",
        target_user: simulationForm.target_user,
        target_device: simulationForm.target_device,
        intensity_level: simulationForm.intensity_level as "Low" | "Medium" | "High",
        duration_minutes: simulationForm.duration_minutes,
        training_mode: simulationForm.training_mode,
        expected_detection: simulationForm.expected_detection,
      });
      setSelectedSimulation(simulation);
      setStatusMessage(
        simulation.status === "Completed"
          ? "Simulation executed and telemetry pushed through the SOC pipeline."
          : "Simulation scheduled in the lab environment.",
      );
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to create simulation.");
    } finally {
      setBusy(false);
    }
  }

  async function handleStartSimulation(simulationId: string) {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      const result = await startSimulation(token, simulationId);
      setStatusMessage(result.message);
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to start simulation.");
    } finally {
      setBusy(false);
    }
  }

  async function handleStopSimulation(simulationId: string) {
    if (!token) {
      return;
    }
    setBusy(true);
    try {
      const result = await stopSimulation(token, simulationId);
      setStatusMessage(result.message);
      await refreshAll();
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to stop simulation.");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <main className="shell">
        <section className="hero">
          <div>
            <p className="eyebrow">Security Operations Center Platform</p>
            <h1>SOC-CyBe</h1>
            <p className="heroCopy">
              Security Operations Center - Cyber Behavior Engine for real-time detection, investigation,
              response, and security posture monitoring.
            </p>
          </div>
          <div className="panel panel--glow authPanel">
            <div className="sectionHeading">
              <h2>Operator Login</h2>
              <span>JWT + Zero Trust session</span>
            </div>
            <div style={{ marginBottom: "1rem", padding: "1rem", backgroundColor: "#f0f0f0", borderRadius: "4px" }}>
              <p style={{ margin: "0 0 0.5rem 0", fontWeight: "bold" }}>Demo Credentials:</p>
              <p style={{ margin: "0.25rem 0" }}>Email: <code>admin@soc-cybe.io</code></p>
              <p style={{ margin: "0.25rem 0" }}>Password: <code>AdminZeroTrust!2026</code></p>
            </div>
            <form className="formGrid" onSubmit={handleLoginSubmit}>
              <label className="field">
                <span>Email</span>
                <input
                  value={loginForm.email}
                  onChange={(event) => setLoginForm((current) => ({ ...current, email: event.target.value }))}
                  type="email"
                  required
                />
              </label>
              <label className="field">
                <span>Password</span>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <input
                    value={loginForm.password}
                    onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
                    type={showPassword ? "text" : "password"}
                    required
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      padding: "0.5rem 0.75rem",
                      backgroundColor: "#f0f0f0",
                      border: "1px solid #ccc",
                      borderRadius: "4px",
                      cursor: "pointer",
                      fontSize: "0.875rem",
                    }}
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </label>
              <label className="field">
                <span>Client IP</span>
                <input
                  value={loginForm.ipAddress}
                  onChange={(event) => setLoginForm((current) => ({ ...current, ipAddress: event.target.value }))}
                  required
                />
              </label>
              <label className="field">
                <span>Device ID</span>
                <input
                  value={loginForm.deviceId}
                  onChange={(event) => setLoginForm((current) => ({ ...current, deviceId: event.target.value }))}
                  required
                />
              </label>
              <button className="actionButton" disabled={busy} type="submit">
                {busy ? "Authenticating..." : "Enter SOC Console"}
              </button>
            </form>
            <p className="statusLine">{statusMessage}</p>
            {statusMessage.includes("Failed to fetch") && (
              <p style={{ color: "#d32f2f", marginTop: "0.5rem", fontSize: "0.875rem" }}>
                ⚠️ Backend not running. Start it with: <code>uvicorn app.main:app --reload --app-dir apps/backend</code>
              </p>
            )}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Security Operations Center Platform</p>
          <h1>SOC-CyBe</h1>
          <p className="heroCopy">
            Interactive SOC workflow console with AI anomaly detection, real-time alert streaming, response
            playbooks, and role-aware investigation controls.
          </p>
        </div>
        <div className="heroGrid">
          <div className="panel panel--glow">
            <span className="panelLabel">Session Context</span>
            <strong>{user?.email}</strong>
            <p>
              Role {user?.role} · Request decision {user?.zero_trust_decision} · Stream {streamState}
            </p>
          </div>
          <div className="panel">
            <span className="panelLabel">Gateway Status</span>
            <strong>{data.gatewayStatus.api_threat_detection ?? "enabled"}</strong>
            <p>JWT auth, request validation, rate limiting, and session tracking remain enforced.</p>
            <div className="buttonRow">
              <button className="actionButton actionButton--ghost" onClick={refreshAll} disabled={busy || loading}>
                Refresh
              </button>
              <button className="actionButton actionButton--ghost" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="metricsGrid">
        {topMetrics.map((metric) => (
          <article key={metric.label} className="panel metricCard">
            <span className="panelLabel">{metric.label}</span>
            <strong>{metric.value}</strong>
            <span className="metricDelta">{metric.delta}</span>
          </article>
        ))}
      </section>

      <section className="contentGrid">
        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Live Alert Feed</h2>
            <span>{loading ? "loading" : statusMessage}</span>
          </div>
          <div className="stack">
            {data.alerts.map((alert) => (
              <button
                key={alert.id}
                className="listRow buttonCard"
                type="button"
                onClick={() => setSelectedAlert(alert)}
              >
                <div>
                  <span className={`severity severity--${severityTone(alert.severity)}`}>{alert.severity}</span>
                  <strong>{alert.title}</strong>
                  <span>
                    {alert.source} · {alert.status}
                  </span>
                </div>
                <span>{formatTime(alert.timestamp)}</span>
              </button>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Alert Investigation</h2>
            <span>{selectedAlert ? selectedAlert.id : "select alert"}</span>
          </div>
          {selectedAlert ? (
            <div className="stack">
              <div className="detailBlock">
                <span className={`severity severity--${severityTone(selectedAlert.severity)}`}>{selectedAlert.severity}</span>
                <strong>{selectedAlert.title}</strong>
                <p>{selectedAlert.source} is the affected telemetry source for this alert.</p>
              </div>
              <div className="buttonRow">
                <button className="actionButton" onClick={handleCreateIncidentFromAlert} disabled={!canRespond || busy}>
                  Escalate to Incident
                </button>
                <button className="actionButton actionButton--ghost" onClick={handleOpenCase} disabled={!canRespond || busy}>
                  Open Case
                </button>
              </div>
              {!canRespond ? <p className="statusLine">Current role can review alerts but cannot start response workflows.</p> : null}
            </div>
          ) : (
            <p className="heroCopy">Choose an alert to inspect related evidence and escalate it into the response workflow.</p>
          )}
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>AI Risk Hotlist</h2>
            <span>behavioral anomalies</span>
          </div>
          <div className="stack">
            {riskHotlist.map((finding) => (
              <div key={finding.id} className="listRow listRow--compact">
                <strong>{finding.anomaly_type}</strong>
                <span>
                  Risk {finding.risk_score} · Confidence {finding.confidence_score}% · {finding.device_id ?? "identity signal"}
                </span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Real-Time Attack Graph</h2>
            <span>
              {data.attackGraph?.active_attack_paths ?? 0} active paths · {data.attackGraph?.compromised_devices ?? 0} compromised devices
            </span>
          </div>
          {data.attackGraph ? (
            <>
              <div className="statsStrip">
                <div className="statChip">
                  <span className="panelLabel">High-Risk Users</span>
                  <strong>{data.attackGraph.high_risk_users}</strong>
                </div>
                <div className="statChip">
                  <span className="panelLabel">Ongoing Incidents</span>
                  <strong>{data.attackGraph.ongoing_incidents}</strong>
                </div>
                <div className="statChip">
                  <span className="panelLabel">Graph Nodes</span>
                  <strong>{data.attackGraph.nodes.length}</strong>
                </div>
                <div className="statChip">
                  <span className="panelLabel">Graph Edges</span>
                  <strong>{data.attackGraph.edges.length}</strong>
                </div>
              </div>
              <div className="graphBoard">
                {data.attackGraph.nodes.slice(0, 18).map((node, index) => (
                  <button
                    key={node.id}
                    type="button"
                    className="graphNode"
                    style={{
                      left: `${10 + (index % 6) * 15}%`,
                      top: `${14 + Math.floor(index / 6) * 28}%`,
                      borderColor: node.color,
                      boxShadow: `0 0 24px ${node.color}33`,
                    }}
                    onClick={() => setSelectedGraphNode(node)}
                  >
                    <strong>{node.label}</strong>
                    <span>{node.node_type}</span>
                  </button>
                ))}
              </div>
              <div className="contentSplit">
                <div className="stack">
                  <div className="detailBlock">
                    <strong>{selectedGraphNode?.label ?? "Select a node"}</strong>
                    <p>
                      {selectedGraphNode
                        ? `${selectedGraphNode.node_type} · risk ${selectedGraphNode.risk_score} · alerts ${selectedGraphNode.alert_count}`
                        : "Click a node to inspect entity details, connected context, and threat-intelligence flags."}
                    </p>
                    {selectedGraphNode?.intel_match ? <p>Threat intelligence match detected for this entity.</p> : null}
                  </div>
                  <div className="stack">
                    {data.attackGraph.ai_attack_path_suggestions.map((suggestion) => (
                      <div key={suggestion} className="listRow listRow--compact">
                        <strong>AI Path Analysis</strong>
                        <span>{suggestion}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="stack">
                  {data.attackGraph.edges.slice(0, 8).map((edge) => (
                    <button
                      key={edge.id}
                      type="button"
                      className="listRow buttonCard"
                      onClick={() => setSelectedGraphEdge(edge)}
                    >
                      <div>
                        <span className={`severity severity--${severityTone(edge.severity)}`}>{edge.action}</span>
                        <strong>
                          {edge.source_system} → {edge.destination_system}
                        </strong>
                        <span>{formatTime(edge.timestamp)}</span>
                      </div>
                    </button>
                  ))}
                  {selectedGraphEdge ? (
                    <p className="statusLine">
                      Edge detail: {selectedGraphEdge.action} from {selectedGraphEdge.source_system} to {selectedGraphEdge.destination_system}.
                    </p>
                  ) : null}
                </div>
              </div>
              <div className="stack">
                <div className="sectionHeading">
                  <h2>Timeline Replay</h2>
                  <span>{data.attackGraph.timeline.length} graph events</span>
                </div>
                {data.attackGraph.timeline.slice(0, 8).map((entry) => (
                  <div key={entry.event_id} className="listRow">
                    <div>
                      <span className={`severity severity--${severityTone(entry.severity)}`}>{entry.action}</span>
                      <strong>
                        {entry.actor ?? "unknown"} → {entry.target ?? "context pending"}
                      </strong>
                      <span>{entry.description}</span>
                    </div>
                    <span>{formatTime(entry.timestamp)}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="heroCopy">Attack graph data will appear once the backend has recent security events to correlate into nodes and paths.</p>
          )}
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Related Event Timeline</h2>
            <span>investigation evidence</span>
          </div>
          <div className="stack">
            {relatedThreatEvents.map((event) => (
              <div key={event.id} className="listRow">
                <div>
                  <span className={`severity severity--${severityTone(event.severity)}`}>{event.severity}</span>
                  <strong>{event.event_type}</strong>
                  <span>{event.summary}</span>
                </div>
                <span>{formatTime(event.created_at)}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Incident Queue</h2>
            <span>{data.incidents.length} active tickets</span>
          </div>
          <div className="stack">
            {data.incidents.map((incident) => (
              <button
                key={incident.id}
                className="listRow buttonCard"
                type="button"
                onClick={() => setSelectedIncident(incident)}
              >
                <div>
                  <span className={`severity severity--${severityTone(incident.severity)}`}>{incident.severity}</span>
                  <strong>{incident.title}</strong>
                  <span>
                    {incident.status} · {incident.response_stage}
                  </span>
                </div>
                <span>{incident.owner}</span>
              </button>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Incident Timeline</h2>
            <span>{selectedIncident?.id ?? "none selected"}</span>
          </div>
          <div className="stack">
            {incidentActivities.length > 0 ? (
              incidentActivities.map((activity) => (
                <div key={activity.id} className="listRow listRow--compact">
                  <strong>{activity.activity_type}</strong>
                  <span>{activity.notes}</span>
                  <span>{formatTime(activity.created_at)}</span>
                </div>
              ))
            ) : (
              <p className="heroCopy">Select an incident to view the investigation trail recorded by the backend workflow.</p>
            )}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Detection Rule Library</h2>
            <span>MITRE ATT&CK aligned</span>
          </div>
          <form className="formGrid formGrid--wide" onSubmit={handleCreateRule}>
            <label className="field">
              <span>Rule Name</span>
              <input
                value={ruleForm.rule_name}
                onChange={(event) => setRuleForm((current) => ({ ...current, rule_name: event.target.value }))}
                minLength={4}
                required
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>Severity</span>
              <select
                value={ruleForm.severity_level}
                onChange={(event) => setRuleForm((current) => ({ ...current, severity_level: event.target.value }))}
                disabled={!canManageRules}
              >
                <option>Low</option>
                <option>Medium</option>
                <option>High</option>
                <option>Critical</option>
              </select>
            </label>
            <label className="field">
              <span>MITRE Tactic</span>
              <input
                value={ruleForm.tactic}
                onChange={(event) => setRuleForm((current) => ({ ...current, tactic: event.target.value }))}
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>MITRE Technique</span>
              <input
                value={ruleForm.technique}
                onChange={(event) => setRuleForm((current) => ({ ...current, technique: event.target.value }))}
                disabled={!canManageRules}
              />
            </label>
            <label className="field field--full">
              <span>Response Action</span>
              <input
                value={ruleForm.response_action}
                onChange={(event) => setRuleForm((current) => ({ ...current, response_action: event.target.value }))}
                disabled={!canManageRules}
              />
            </label>
            <label className="field field--full">
              <span>Rule Conditions JSON</span>
              <textarea
                value={ruleForm.event_conditions}
                onChange={(event) => setRuleForm((current) => ({ ...current, event_conditions: event.target.value }))}
                rows={4}
                disabled={!canManageRules}
              />
            </label>
            <div className="buttonRow">
              <button className="actionButton" type="submit" disabled={!canManageRules || busy}>
                Create Rule
              </button>
              <button className="actionButton actionButton--ghost" type="button" disabled={!canManageRules || busy} onClick={handleTrainAI}>
                Retrain AI
              </button>
            </div>
          </form>
          {!canManageRules ? <p className="statusLine">Current role can review detections but cannot change rule policy.</p> : null}
          <div className="stack">
            {data.rules.map((rule) => (
              <div key={rule.id} className="listRow listRow--rule">
                <div>
                  <span className={`severity severity--${severityTone(rule.severity_level)}`}>{rule.severity_level}</span>
                  <strong>{rule.rule_name}</strong>
                  <span>
                    {rule.tactic ?? "Unmapped"} / {rule.technique ?? "Unmapped"} / {rule.mitre_technique_id ?? "No MITRE ID"}
                  </span>
                </div>
                <div className="buttonRow">
                  <button className="actionButton actionButton--ghost" onClick={() => handleToggleRule(rule.id)} disabled={!canManageRules || busy}>
                    {rule.is_active ? "Deactivate" : "Activate"}
                  </button>
                  <button className="actionButton actionButton--ghost" onClick={() => handleTestRule(rule.id)} disabled={busy}>
                    Test
                  </button>
                </div>
              </div>
            ))}
          </div>
          <label className="field field--full">
            <span>Rule Test Payload</span>
            <textarea value={ruleTestPayload} onChange={(event) => setRuleTestPayload(event.target.value)} rows={3} />
          </label>
          {ruleTestResult ? <p className="statusLine">{ruleTestResult}</p> : null}
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Response Playbooks</h2>
            <span>SOAR execution</span>
          </div>
          <div className="stack">
            {data.playbooks.map((playbook) => (
              <div key={playbook.id} className="listRow listRow--compact">
                <strong>{playbook.name}</strong>
                <span>
                  Trigger {playbook.trigger_event} · {playbook.requires_approval ? "approval required" : "automated"}
                </span>
                <button className="actionButton actionButton--ghost" onClick={() => handleExecutePlaybook(playbook.id)} disabled={!canRespond || busy}>
                  Execute
                </button>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Security Posture</h2>
            <span>environment hygiene</span>
          </div>
          <div className="stack">
            {data.posture.map((snapshot) => (
              <div key={snapshot.id} className="listRow listRow--compact">
                <strong>{snapshot.environment_name}</strong>
                <span>
                  Posture {snapshot.posture_score} · Patch {snapshot.patch_status}% · Vulnerabilities {snapshot.vulnerable_software}
                </span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Sessions</h2>
            <span>tracked access</span>
          </div>
          <div className="stack">
            {data.sessions.map((session) => (
              <div key={session.session_id} className="listRow listRow--compact">
                <strong>{session.device_id ?? "unknown-device"}</strong>
                <span>
                  {session.status} · {session.ip_address} · {formatTime(session.last_seen)}
                </span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="sectionHeading">
            <h2>Monitored Devices</h2>
            <span>endpoint coverage</span>
          </div>
          <div className="deviceGrid deviceGrid--single">
            {data.devices.slice(0, 4).map((device) => (
              <div key={device.id} className="deviceCard">
                <span className="panelLabel">{device.type ?? device.device_type ?? "device"}</span>
                <strong>{device.id}</strong>
                <span>{device.location ?? "location pending"}</span>
                <span>Risk {device.risk ?? device.risk_score ?? 0}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Case Management</h2>
            <span>{data.cases.length} active investigations</span>
          </div>
          <label className="field field--full">
            <span>Investigation Notes</span>
            <textarea value={caseNotes} onChange={(event) => setCaseNotes(event.target.value)} rows={3} />
          </label>
          <div className="stack">
            {data.cases.map((caseItem) => (
              <div key={caseItem.id} className="listRow">
                <div>
                  <span className="severity severity--medium">{caseItem.status}</span>
                  <strong>{caseItem.id}</strong>
                  <span>{caseItem.investigation_notes}</span>
                </div>
                <span>{formatTime(caseItem.updated_at)}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Cyber Attack Simulation Lab</h2>
            <span>safe training and validation environment</span>
          </div>
          <form className="formGrid formGrid--wide" onSubmit={handleCreateSimulation}>
            <label className="field">
              <span>Scenario Name</span>
              <input
                value={simulationForm.scenario_name}
                onChange={(event) => setSimulationForm((current) => ({ ...current, scenario_name: event.target.value }))}
                required
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>Scenario Type</span>
              <select
                value={simulationForm.scenario_type}
                onChange={(event) => setSimulationForm((current) => ({ ...current, scenario_type: event.target.value }))}
                disabled={!canManageRules}
              >
                <option value="brute_force">Brute Force Login Attack</option>
                <option value="suspicious_login_location">Suspicious Login Location</option>
                <option value="privilege_escalation">Privilege Escalation Attempt</option>
                <option value="malicious_file_execution">Malicious File Execution</option>
                <option value="data_exfiltration">Data Exfiltration Attempt</option>
              </select>
            </label>
            <label className="field">
              <span>Mode</span>
              <select
                value={simulationForm.mode}
                onChange={(event) => setSimulationForm((current) => ({ ...current, mode: event.target.value }))}
                disabled={!canManageRules}
              >
                <option value="manual">Manual</option>
                <option value="scheduled">Scheduled</option>
                <option value="randomized">Randomized</option>
              </select>
            </label>
            <label className="field">
              <span>Intensity</span>
              <select
                value={simulationForm.intensity_level}
                onChange={(event) => setSimulationForm((current) => ({ ...current, intensity_level: event.target.value }))}
                disabled={!canManageRules}
              >
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
              </select>
            </label>
            <label className="field">
              <span>Target User</span>
              <input
                value={simulationForm.target_user}
                onChange={(event) => setSimulationForm((current) => ({ ...current, target_user: event.target.value }))}
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>Target Device</span>
              <input
                value={simulationForm.target_device}
                onChange={(event) => setSimulationForm((current) => ({ ...current, target_device: event.target.value }))}
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>Duration Minutes</span>
              <input
                type="number"
                min={1}
                max={120}
                value={simulationForm.duration_minutes}
                onChange={(event) =>
                  setSimulationForm((current) => ({ ...current, duration_minutes: Number(event.target.value) || 1 }))
                }
                disabled={!canManageRules}
              />
            </label>
            <label className="field">
              <span>Training Mode</span>
              <select
                value={simulationForm.training_mode ? "enabled" : "disabled"}
                onChange={(event) =>
                  setSimulationForm((current) => ({ ...current, training_mode: event.target.value === "enabled" }))
                }
                disabled={!canManageRules}
              >
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </label>
            <label className="field field--full">
              <span>Expected Detection Outcome</span>
              <textarea
                value={simulationForm.expected_detection}
                onChange={(event) => setSimulationForm((current) => ({ ...current, expected_detection: event.target.value }))}
                rows={3}
                disabled={!canManageRules}
              />
            </label>
            <div className="buttonRow">
              <button className="actionButton" type="submit" disabled={!canManageRules || busy}>
                Launch Simulation
              </button>
            </div>
          </form>
          {!canManageRules ? <p className="statusLine">Simulation control is restricted to administrators in this MVP.</p> : null}
          <div className="stack">
            {data.simulations.map((simulation) => (
              <button
                key={simulation.id}
                className="listRow buttonCard"
                type="button"
                onClick={() => setSelectedSimulation(simulation)}
              >
                <div>
                  <span className={`severity severity--${severityTone(simulation.intensity_level === "High" ? "High" : simulation.intensity_level === "Low" ? "Low" : "Medium")}`}>
                    {simulation.intensity_level}
                  </span>
                  <strong>{simulation.scenario_name}</strong>
                  <span>
                    {simulation.scenario_type} · {simulation.status} · {simulation.safety_status}
                  </span>
                </div>
                <span>{formatTime(simulation.started_at ?? simulation.scheduled_for ?? simulation.completed_at ?? undefined)}</span>
              </button>
            ))}
          </div>
        </article>

        <article className="panel panel--wide">
          <div className="sectionHeading">
            <h2>Simulation Timeline</h2>
            <span>{selectedSimulation?.id ?? "select lab run"}</span>
          </div>
          {selectedSimulation ? (
            <>
              <div className="detailBlock">
                <strong>{selectedSimulation.scenario_name}</strong>
                <p>
                  {selectedSimulation.safety_notes} Target {selectedSimulation.target_user ?? "lab identity"} on{" "}
                  {selectedSimulation.target_device ?? "lab endpoint"}.
                </p>
                <p>
                  Expected detection: {selectedSimulation.expected_detection}
                </p>
              </div>
              <div className="buttonRow">
                <button
                  className="actionButton actionButton--ghost"
                  onClick={() => handleStartSimulation(selectedSimulation.id)}
                  disabled={!canManageRules || busy || selectedSimulation.status === "Completed" || selectedSimulation.status === "Stopped"}
                >
                  Start
                </button>
                <button
                  className="actionButton actionButton--ghost"
                  onClick={() => handleStopSimulation(selectedSimulation.id)}
                  disabled={!canManageRules || busy || selectedSimulation.status === "Completed"}
                >
                  Stop
                </button>
              </div>
              <div className="stack">
                {selectedSimulation.timeline.length > 0 ? (
                  selectedSimulation.timeline.map((entry, index) => (
                    <div key={`${selectedSimulation.id}-${index}`} className="listRow">
                      <div>
                        <span className="severity severity--medium">{String(entry.phase ?? "Timeline")}</span>
                        <strong>{String(entry.event_type ?? "event")}</strong>
                        <span>{String(entry.description ?? "Simulation activity recorded.")}</span>
                      </div>
                      <span>{formatTime(String(entry.timestamp ?? ""))}</span>
                    </div>
                  ))
                ) : (
                  <p className="heroCopy">This simulation has not emitted a timeline yet. Start or launch it to drive telemetry into SOC-CyBe.</p>
                )}
              </div>
              <p className="statusLine">
                Alerts {String(selectedSimulation.detection_summary.alerts_created ?? 0)} · Max AI risk{" "}
                {String(selectedSimulation.detection_summary.max_ai_risk_score ?? 0)} · Incident{" "}
                {String(selectedSimulation.detection_summary.incident_id ?? "pending")}
              </p>
            </>
          ) : (
            <p className="heroCopy">Select a simulation to review its attack progression, expected detections, and response validation outcome.</p>
          )}
        </article>

        {canReadLogs ? (
          <article className="panel panel--wide">
            <div className="sectionHeading">
              <h2>Audit Context</h2>
              <span>UI actions are logged server-side</span>
            </div>
            <p className="heroCopy">
              Every login, rule change, playbook execution, and investigation action in this UI is routed through
              authenticated backend APIs and captured by the SOC-CyBe audit layer for later review.
            </p>
          </article>
        ) : null}
      </section>
    </main>
  );
}
