import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Flame,
  KeyRound,
  Network,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { Badge, Button, Panel, RiskBadge, SectionHead } from '@/components/ui-kit';

interface SimulationResult {
  attackType: string;
  event: {
    id: number;
    anomalyScore: number;
    riskLevel: 'Low' | 'Medium' | 'High';
    classification: 'Normal' | 'Suspicious';
    srcBytes: number;
    dstBytes: number;
    packetCount: number;
    connectionRate: number;
    timestamp: string;
  };
  mitigationApplied?: {
    id: string;
    actionTaken: string;
    riskLevel: string;
    expiresAt: string;
  } | null;
  treeStats: {
    treesEvaluated: number;
    averageDepth: number;
    featuresUsed: number;
  };
  gruStats?: {
    reconstructionError: number;
    normalityConfidence: number;
    comprehensiveRiskScore: number;
    riskLevel: string;
  };
}

export function AttackSimulatorPage() {
  const [loading, setLoading] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<SimulationResult | null>(null);
  const [activeRules, setActiveRules] = useState<any[]>([]);

  const triggerAttack = async (type: string) => {
    setLoading(type);
    try {
      const res = await fetch('/api/intrusion/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attackType: type }),
      });
      if (res.ok) {
        const data = await res.json();
        setLastResult(data);
        fetchRules();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(null);
    }
  };

  const fetchRules = async () => {
    try {
      const res = await fetch('/api/intrusion/mitigation-rules');
      if (res.ok) {
        const data = await res.json();
        setActiveRules(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const attackPresets = [
    {
      id: 'DDoS',
      name: 'DDoS / SYN Flood',
      detail: 'High packet volume & connection spikes',
      icon: Flame,
      color: 'border-red-500/30 bg-red-500/10 text-red-400',
    },
    {
      id: 'Exfiltration',
      name: 'Data Exfiltration',
      detail: 'Massive outbound TX byte burst',
      icon: Network,
      color: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
    },
    {
      id: 'PortScan',
      name: 'Port Scan Sweep',
      detail: 'Rapid connection rate on low bytes',
      icon: Zap,
      color: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
    },
    {
      id: 'BruteForce',
      name: 'Brute-Force Auth',
      detail: 'Rapid consecutive login failures',
      icon: KeyRound,
      color: 'border-purple-500/30 bg-purple-500/10 text-purple-400',
    },
  ];

  return (
    <div className="animate-rise space-y-7">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
            Red Team / Attack Sandbox
          </div>
          <h1 className="text-3xl font-extrabold tracking-[-.055em] md:text-4xl">
            Interactive Attack Simulator
          </h1>
          <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
            Inject synthetic threat vectors to evaluate Isolation Forest tree traversal & automated IPS mitigation.
          </p>
        </div>
        <Badge tone="good">Active Sandbox Mode</Badge>
      </div>

      {/* Preset Action Grid */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {attackPresets.map(({ id, name, detail, icon: Icon, color }) => (
          <Panel key={id} className={`p-4 transition hover:border-[hsl(var(--primary)/.4)]`}>
            <div className="flex flex-col justify-between gap-4">
              <div className="flex items-start justify-between">
                <div className={`grid size-9 place-items-center rounded-xl border ${color}`}>
                  <Icon size={18} />
                </div>
                <Badge tone="warn">Attack Vector</Badge>
              </div>
              <div>
                <div className="text-sm font-bold">{name}</div>
                <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">{detail}</div>
              </div>
              <Button
                data-testid={`btn-simulate-${id.toLowerCase()}`}
                loading={loading === id}
                onClick={() => triggerAttack(id)}
                className="w-full text-xs font-bold"
              >
                Inject Attack Vector
              </Button>
            </div>
          </Panel>
        ))}
      </div>

      {/* Evaluation Results & Active IPS */}
      <div className="grid gap-5 xl:grid-cols-[1.25fr_.75fr]">
        <Panel className="p-5">
          <SectionHead
            eyebrow="AI Tree Traversal"
            title="Isolation Forest Evaluation"
            detail="32 Decision Trees Evaluated on 6D Feature Vector"
          />

          {lastResult ? (
            <div className="mt-4 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--muted)/.4)] p-4">
                <div>
                  <div className="mono text-[10px] uppercase tracking-[.15em] text-[hsl(var(--muted-foreground))]">
                    Attack Vector Analyzed
                  </div>
                  <div className="mt-1 text-lg font-extrabold">{lastResult.attackType} Simulation</div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="mono text-[10px] uppercase text-[hsl(var(--muted-foreground))]">
                      Anomaly Score
                    </div>
                    <div className="mono text-2xl font-extrabold text-[hsl(var(--primary))]">
                      {Math.round(lastResult.event.anomalyScore * 100)}%
                    </div>
                  </div>
                  <RiskBadge risk={lastResult.event.riskLevel} />
                </div>
              </div>

              {/* Vector Features Table */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-[hsl(var(--border))] p-3">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Packets / Sec</div>
                  <div className="mono mt-1 text-base font-bold">{lastResult.event.packetCount}</div>
                </div>
                <div className="rounded-lg border border-[hsl(var(--border))] p-3">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">TX Bytes</div>
                  <div className="mono mt-1 text-base font-bold">
                    {(lastResult.event.srcBytes / 1024).toFixed(1)} KB
                  </div>
                </div>
                <div className="rounded-lg border border-[hsl(var(--border))] p-3">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Connection Rate</div>
                  <div className="mono mt-1 text-base font-bold">{lastResult.event.connectionRate}/s</div>
                </div>
              </div>

              {/* Tree Metrics */}
              <div className="rounded-xl border border-[hsl(var(--primary)/.25)] bg-[hsl(var(--primary)/.05)] p-4">
                <div className="mb-2 flex items-center justify-between">
                  <span className="mono text-xs font-bold text-[hsl(var(--primary))]">
                    Tree Path Isolation Depth
                  </span>
                  <span className="mono text-xs text-[hsl(var(--muted-foreground))]">
                    Depth: {lastResult.treeStats.averageDepth} / 6.0
                  </span>
                </div>
                <div className="h-2 rounded-full bg-[hsl(var(--muted))]">
                  <div
                    className="h-full rounded-full bg-[hsl(var(--primary))]"
                    style={{
                      width: `${Math.min(
                        100,
                        (1 - lastResult.event.anomalyScore) * 100,
                      )}%`,
                    }}
                  />
                </div>
                <p className="mt-2 text-[11px] text-[hsl(var(--muted-foreground))]">
                  Anomalous flows are isolated at shallower tree depths due to distinct statistical feature partitioning.
                </p>
              </div>

              {lastResult.gruStats && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="mono text-xs font-bold text-amber-400">
                      GRU Sequence Autoencoder Evaluation (Paper §3.3.2)
                    </span>
                    <Badge tone={lastResult.gruStats.riskLevel === 'High' ? 'danger' : 'warn'}>
                      {lastResult.gruStats.riskLevel} Risk
                    </Badge>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Reconstruction L_rec</div>
                      <div className="mono font-bold">{lastResult.gruStats.reconstructionError}</div>
                    </div>
                    <div>
                      <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Normality D(X)</div>
                      <div className="mono font-bold">{Math.round(lastResult.gruStats.normalityConfidence * 100)}%</div>
                    </div>
                    <div>
                      <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Composite R(X)</div>
                      <div className="mono font-bold text-[hsl(var(--primary))]">
                        {Math.round(lastResult.gruStats.comprehensiveRiskScore * 100)}%
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-[hsl(var(--muted-foreground))]">
              Click any attack preset above to trigger the Isolation Forest ML evaluation.
            </div>
          )}
        </Panel>

        {/* Active Defense Rules Panel */}
        <Panel className="p-5">
          <SectionHead
            eyebrow="Autonomous Defense"
            title="Active IPS Mitigation"
            detail="Automated Socket Throttling Rules"
          />

          <div className="mt-4 space-y-3">
            {activeRules.length === 0 ? (
              <div className="py-8 text-center text-xs text-[hsl(var(--muted-foreground))]">
                No active mitigation rules triggered yet. High-risk attack vectors trigger automated active defense rules.
              </div>
            ) : (
              activeRules.map((rule) => (
                <div
                  key={rule.id}
                  className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="mono font-bold text-red-400">{rule.id}</span>
                    <Badge tone="warn">{rule.riskLevel} Risk</Badge>
                  </div>
                  <div className="mt-1.5 font-semibold">{rule.actionTaken}</div>
                  <div className="mono mt-2 text-[10px] text-[hsl(var(--muted-foreground))]">
                    Target: {rule.targetInterface} · Score: {Math.round(rule.anomalyScore * 100)}%
                  </div>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
