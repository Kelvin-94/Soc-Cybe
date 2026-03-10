/*
SOC-CyBe Security Platform
Module: Frontend Demo Data

Purpose:
This file contains structured placeholder data used by the dashboard UI.
It lets the frontend communicate the intended SOC experience before every
panel is wired to live backend APIs.

Developer Note:
As more widgets move to real endpoints, keep replacing these placeholders
instead of expanding them indefinitely.
*/

export const metrics = [
  { label: "Threats Blocked", value: "842", delta: "+14.2%" },
  { label: "Suspicious Logins", value: "19", delta: "+8.1%" },
  { label: "API Abuse Attempts", value: "63", delta: "+5.4%" },
  { label: "Devices at Risk", value: "7", delta: "-2.8%" },
];

export const pipelineSteps = [
  "Data Sources",
  "Ingestion",
  "Processing",
  "Detection",
  "Response",
  "Visualization",
];

export const sourceCoverage = [
  { label: "Endpoint Logs", detail: "Windows, Linux, process, file, login telemetry" },
  { label: "Network Logs", detail: "Firewall, DNS, proxy, VPN, and flow records" },
  { label: "Cloud Logs", detail: "AWS, Azure, and GCP activity and audit trails" },
  { label: "Application Logs", detail: "API access, auth events, DB access, role changes" },
];

export const analyticsSeries = [
  { label: "00", threats: 18, api: 11, auth: 9 },
  { label: "04", threats: 28, api: 17, auth: 14 },
  { label: "08", threats: 44, api: 21, auth: 19 },
  { label: "12", threats: 58, api: 34, auth: 24 },
  { label: "16", threats: 42, api: 27, auth: 20 },
  { label: "20", threats: 36, api: 23, auth: 16 },
];

export const threatCounters = [
  { label: "Critical Alerts", value: 6, tone: "critical" },
  { label: "Open Investigations", value: 14, tone: "high" },
  { label: "Blocked IPs", value: 87, tone: "medium" },
  { label: "Trusted Sessions", value: 321, tone: "low" },
];

export const networkNodes = [
  { id: "Gateway", x: 14, y: 30, tone: "low" },
  { id: "API", x: 34, y: 18, tone: "medium" },
  { id: "IAM", x: 54, y: 30, tone: "low" },
  { id: "SIEM", x: 72, y: 14, tone: "high" },
  { id: "EDR", x: 78, y: 48, tone: "critical" },
  { id: "DB", x: 48, y: 62, tone: "medium" },
  { id: "SOC", x: 22, y: 60, tone: "low" },
];

export const liveMonitors = [
  { label: "Packet Inspection", value: "98.4%", status: "Healthy" },
  { label: "API Auth Success", value: "94.1%", status: "Watching" },
  { label: "Endpoint Integrity", value: "89.7%", status: "At Risk" },
  { label: "SIEM Ingest", value: "32k/min", status: "Healthy" },
];

export const alerts = [
  {
    id: "ALT-401",
    severity: "Critical",
    title: "Credential stuffing burst detected",
    source: "Auth Gateway",
    status: "Investigating",
    time: "03m ago",
  },
  {
    id: "ALT-402",
    severity: "High",
    title: "Privilege escalation attempt on finance API",
    source: "API Shield",
    status: "Escalated",
    time: "10m ago",
  },
  {
    id: "ALT-403",
    severity: "Medium",
    title: "Anomalous login from new geography",
    source: "Identity Monitor",
    status: "Queued",
    time: "18m ago",
  },
  {
    id: "ALT-404",
    severity: "High",
    title: "Risk score spike on privileged responder account",
    source: "Risk Engine",
    status: "Review",
    time: "22m ago",
  },
];

export const incidents = [
  {
    id: "INC-2201",
    title: "Compromised API token investigation",
    severity: "Critical",
    stage: "Containment",
    status: "Investigating",
    asset: "finance-api",
  },
  {
    id: "INC-2202",
    title: "Endpoint malware triage",
    severity: "High",
    stage: "Eradication",
    status: "Contained",
    asset: "endpoint-lt-203",
  },
];

export const devices = [
  { id: "DEV-001", type: "Workstation", location: "Johannesburg", risk: 31 },
  { id: "DEV-002", type: "Mobile", location: "Frankfurt", risk: 66 },
  { id: "DEV-003", type: "Server", location: "Virginia", risk: 19 },
];

export const alertDistribution = [
  { label: "Identity", value: 32 },
  { label: "API", value: 24 },
  { label: "Endpoint", value: 17 },
  { label: "Network", value: 11 },
];

export const roles = [
  { name: "Admin", focus: "Users, policy, full response coverage" },
  { name: "SOC Analyst", focus: "Detection, triage, investigation" },
  { name: "Incident Responder", focus: "Containment, eradication, recovery" },
  { name: "Viewer", focus: "Read-only monitoring and reporting" },
];

export const terminalFeed = [
  "[11:00:01] TLS 1.3 tunnel validated for api-gateway-03",
  "[11:00:07] Risk engine recalculated trust score for usr_analyst_002",
  "[11:00:11] Immutable audit block appended for permission-change event",
  "[11:00:15] Suspicious IP reputation drop detected from edge-node-11",
  "[11:00:21] Step-up authentication challenge triggered for privileged session",
];

export const investigationStats = [
  { label: "Open Tickets", value: "14" },
  { label: "Critical Cases", value: "3" },
  { label: "Containment Stage", value: "5" },
  { label: "MTTC", value: "38m" },
];

export const responseWorkflow = [
  "Identification",
  "Containment",
  "Eradication",
  "Recovery",
  "Lessons Learned",
];
