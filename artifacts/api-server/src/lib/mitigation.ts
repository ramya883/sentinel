import { appendAuditLog } from "./security";
import { broadcastRealtimeEvent } from "./sse";

export interface ActiveMitigationRule {
  id: string;
  timestamp: string;
  attackType: string;
  riskLevel: "Low" | "Medium" | "High";
  anomalyScore: number;
  actionTaken: string;
  targetInterface: string;
  status: "Active" | "Expired" | "Overridden";
  expiresAt: string;
}

const activeRules: ActiveMitigationRule[] = [];
let ruleCounter = 1;

export async function processMitigation(event: {
  userId?: number | null;
  actor?: string;
  anomalyScore: number;
  riskLevel: "Low" | "Medium" | "High";
  classification: string;
  srcBytes: number;
  dstBytes: number;
}): Promise<ActiveMitigationRule | null> {
  if (event.anomalyScore < 0.65 && event.riskLevel !== "High") {
    return null;
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);

  let actionTaken = "Traffic Rate-Limited (50% Bandwidth Cap)";
  if (event.anomalyScore >= 0.85) {
    actionTaken = "Automated Socket Disconnect & Hardware Isolation";
  } else if (event.anomalyScore >= 0.75) {
    actionTaken = "Strict Packet Throttling & Step-Up Auth Enforcement";
  }

  const rule: ActiveMitigationRule = {
    id: `IPS-RULE-${String(ruleCounter++).padStart(4, "0")}`,
    timestamp: now.toISOString(),
    attackType: event.classification === "Suspicious" ? "High-Volume Anomaly" : "Heuristic Risk Alert",
    riskLevel: event.riskLevel,
    anomalyScore: event.anomalyScore,
    actionTaken,
    targetInterface: "eth0 / local-adapter",
    status: "Active",
    expiresAt: expiresAt.toISOString(),
  };

  activeRules.unshift(rule);
  if (activeRules.length > 20) {
    activeRules.pop();
  }

  await appendAuditLog({
    userId: event.userId ?? null,
    eventType: "Active Defense Applied",
    description: `Automated IPS triggered ${rule.id}: ${actionTaken} (Score: ${intPct(event.anomalyScore)}%).`,
    riskScore: event.anomalyScore,
    actor: event.actor ?? "Active Mitigation Engine",
  });

  broadcastRealtimeEvent("mitigation_triggered", rule);

  return rule;
}

function intPct(score: number): number {
  return Math.round(score * 100);
}

export function getActiveMitigationRules(): ActiveMitigationRule[] {
  return activeRules;
}
