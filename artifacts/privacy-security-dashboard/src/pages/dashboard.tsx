import { useEffect, useState } from 'react';
import { Activity, ArrowUpRight, Cpu, Database, Fingerprint, KeyRound, RefreshCw, ShieldAlert, Sparkles, UsersRound, Zap } from 'lucide-react';
import { useGetDashboard } from '@workspace/api-client-react';
import { Link } from 'wouter';
import { Badge, Button, Panel, QueryState, RiskBadge, SectionHead } from '@/components/ui-kit';

const formatTime = (value: string) => new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const distributionColors = ['bg-[hsl(var(--primary))]', 'bg-[hsl(var(--accent))]', 'bg-[hsl(var(--chart-3))]', 'bg-[hsl(var(--chart-4))]'];

interface MarkovState {
  currentState: string;
  stateIndex: number;
  transitionProbabilities: Record<string, number>;
  observationVector: {
    abnormalAccessRate: number;
    encryptionLatencyMs: number;
    keyRotationFrequency: number;
    aiFalsePositiveRate: number;
    threatIntensity: number;
  };
  strategyVector: {
    encryptionStrength: number;
    detectionSensitivity: number;
    authenticationThreshold: number;
    keyRotationMinutes: number;
    blockchainSyncFrequencySecs: number;
  };
  utilityScore: {
    accuracyBenefit: number;
    overheadCost: number;
    netUtility: number;
  };
}

interface EncryptionStatus {
  activeLevel: number;
  algorithm: string;
  sessionKeyFingerprint: string;
  keyRotationEpoch: number;
  nextRotationInSeconds: number;
  perturbationVectorsGenerated: number;
}

export function DashboardPage() {
  const dashboard = useGetDashboard();
  const data = dashboard.data;

  const [markov, setMarkov] = useState<MarkovState | null>(null);
  const [encryption, setEncryption] = useState<EncryptionStatus | null>(null);
  const [steppingMarkov, setSteppingMarkov] = useState(false);
  const [rotatingKey, setRotatingKey] = useState(false);

  const fetchAdvancedEngines = async () => {
    try {
      const [mRes, eRes] = await Promise.all([
        fetch('/api/defense/markov-state'),
        fetch('/api/encryption/status'),
      ]);
      if (mRes.ok) setMarkov(await mRes.json());
      if (eRes.ok) setEncryption(await eRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchAdvancedEngines();
    const interval = setInterval(fetchAdvancedEngines, 8000);
    return () => clearInterval(interval);
  }, []);

  const triggerMarkovStep = async (state?: string) => {
    setSteppingMarkov(true);
    try {
      const res = await fetch('/api/defense/markov-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state ? { state } : { threatScore: 0.6 }),
      });
      if (res.ok) {
        setMarkov(await res.json());
      }
    } finally {
      setSteppingMarkov(false);
    }
  };

  const triggerKeyRotation = async () => {
    setRotatingKey(true);
    try {
      const res = await fetch('/api/encryption/rotate-key', { method: 'POST' });
      if (res.ok) {
        setEncryption(await res.json());
      }
    } finally {
      setRotatingKey(false);
    }
  };

  if (dashboard.isLoading) return <PageLoading title="Overview" />;
  if (dashboard.isError || !data) return <QueryState error retry={() => dashboard.refetch()} />;

  const stats = [
    { label: 'Protected users', value: data.totalUsers, hint: 'active identities', icon: UsersRound, tone: 'text-[hsl(var(--primary))]' },
    { label: 'Threats detected', value: data.threatsDetected, hint: 'this workspace', icon: ShieldAlert, tone: 'text-[hsl(var(--accent))]' },
    { label: 'High-risk events', value: data.highRiskEvents, hint: 'needs review', icon: Activity, tone: 'text-[hsl(var(--chart-3))]' },
    { label: 'Average trust', value: `${data.averageTrustScore}`, hint: 'out of 100', icon: Fingerprint, tone: 'text-[hsl(var(--chart-4))]' },
  ];

  return (
    <div className="animate-rise space-y-7">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
            Command center / daily brief
          </div>
          <h1 className="text-3xl font-extrabold tracking-[-.055em] md:text-4xl">
            Autonomous Security Reinforcement
          </h1>
          <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
            Closed-loop AI defense, Markov threat situation awareness, and cryptographic integrity.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone="good">Adaptive Protection Active</Badge>
          {markov && (
            <Badge tone={markov.currentState === 'Critical' ? 'danger' : markov.currentState === 'UnderAttack' ? 'warn' : 'info'}>
              Markov: {markov.currentState}
            </Badge>
          )}
        </div>
      </div>

      {/* Top 4 Stats */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map(({ label, value, hint, icon: Icon, tone }, index) => (
          <Panel
            key={label}
            className={`relative overflow-hidden p-4 ${index === 0 ? 'border-[hsl(var(--primary)/.35)]' : ''}`}
            data-testid={`card-stat-${label.toLowerCase().replaceAll(' ', '-')}`}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="text-xs font-semibold text-[hsl(var(--muted-foreground))]">{label}</div>
                <div className="mt-3 text-3xl font-extrabold tracking-[-.06em]">{value}</div>
                <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">{hint}</div>
              </div>
              <Icon size={19} className={tone} />
            </div>
          </Panel>
        ))}
      </div>

      {/* ADVANCED SECTION: Markov Situation Awareness & 5D Defense Vector */}
      {markov && (
        <Panel className="p-6 border-[hsl(var(--primary)/.3)] bg-[hsl(var(--card))]">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <SectionHead
              eyebrow="Research Engine §3.5"
              title="Threat Situation Awareness & Dynamic Evolution (Markov & RL)"
              detail="State space transition model P_ij optimizes 5D strategy vector Θ_t maximizing net utility U_t = ω1·A_t - ω2·C_t."
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                className="text-xs"
                loading={steppingMarkov}
                onClick={() => triggerMarkovStep()}
              >
                <Zap size={13} /> Step Transition
              </Button>
            </div>
          </div>

          <div className="mt-4 grid gap-5 lg:grid-cols-[1fr_1.3fr]">
            {/* Markov State Transition Box */}
            <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
              <div className="flex items-center justify-between">
                <span className="mono text-xs font-bold text-[hsl(var(--muted-foreground))]">Current Markov State (S_t)</span>
                <span className="mono text-xs font-extrabold text-[hsl(var(--primary))]">
                  State [{markov.stateIndex}] : {markov.currentState}
                </span>
              </div>

              {/* State Transition Probabilities Bar */}
              <div className="mt-4 space-y-2">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">
                  Transition Probabilities P(S_&#123;t+1&#125; | S_t):
                </div>
                {Object.entries(markov.transitionProbabilities).map(([st, prob]) => (
                  <div key={st} className="flex items-center gap-2 text-xs">
                    <span className="mono w-28 truncate text-[11px] font-semibold">{st}</span>
                    <div className="h-1.5 flex-1 rounded-full bg-[hsl(var(--muted))]">
                      <div
                        className="h-full rounded-full bg-[hsl(var(--primary))]"
                        style={{ width: `${Math.round(prob * 100)}%` }}
                      />
                    </div>
                    <span className="mono text-[10px] w-10 text-right">{Math.round(prob * 100)}%</span>
                  </div>
                ))}
              </div>

              {/* Quick state triggers */}
              <div className="mt-4 pt-3 border-t border-[hsl(var(--border))] flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] text-[hsl(var(--muted-foreground))] mr-1">Simulate State:</span>
                {['Normal', 'Reconnaissance', 'Elevated', 'UnderAttack', 'Critical'].map((s) => (
                  <button
                    key={s}
                    onClick={() => triggerMarkovStep(s)}
                    className={`rounded px-2 py-0.5 text-[10px] font-bold border transition ${
                      markov.currentState === s
                        ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]'
                        : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--muted))]'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* 5-Dimensional Strategy Vector Theta_t */}
            <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
              <div className="flex items-center justify-between">
                <span className="mono text-xs font-bold text-[hsl(var(--muted-foreground))]">
                  5D Defense Strategy Vector (Θ_t = Φ(S_t))
                </span>
                <span className="mono text-[11px] font-bold text-emerald-500">
                  Net Utility U_t: +{markov.utilityScore.netUtility}
                </span>
              </div>

              <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">θ_enc (Cipher Level)</div>
                  <div className="mono mt-1 text-base font-extrabold text-[hsl(var(--primary))]">
                    Level {markov.strategyVector.encryptionStrength} / 5
                  </div>
                </div>

                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">θ_det (Detection Sens.)</div>
                  <div className="mono mt-1 text-base font-extrabold text-[hsl(var(--chart-3))]">
                    {Math.round(markov.strategyVector.detectionSensitivity * 100)}%
                  </div>
                </div>

                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">θ_auth (Auth Threshold)</div>
                  <div className="mono mt-1 text-base font-extrabold text-[hsl(var(--chart-4))]">
                    {markov.strategyVector.authenticationThreshold} Trust
                  </div>
                </div>

                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">θ_rot (Key Rotation)</div>
                  <div className="mono mt-1 text-base font-extrabold">
                    Every {markov.strategyVector.keyRotationMinutes}m
                  </div>
                </div>

                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">θ_chain (Ledger Sync)</div>
                  <div className="mono mt-1 text-base font-extrabold">
                    {markov.strategyVector.blockchainSyncFrequencySecs}s
                  </div>
                </div>

                <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Accuracy Benefit A_t</div>
                  <div className="mono mt-1 text-base font-extrabold text-emerald-400">
                    +{markov.utilityScore.accuracyBenefit}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* Main Grid: Signal Stream & Side Panels */}
      <div className="grid gap-5 xl:grid-cols-[1.25fr_.75fr]">
        <Panel className="p-5">
          <SectionHead
            eyebrow="Signal stream"
            title="Recent activity"
            detail="Events that shifted the posture of your workspace."
            action={
              <Link href="/audit-logs" data-testid="link-view-audit" className="flex items-center gap-1 text-xs font-bold text-[hsl(var(--primary))]">
                View audit <ArrowUpRight size={14} />
              </Link>
            }
          />
          {data.recentActivity.length === 0 ? (
            <QueryState empty />
          ) : (
            <div className="divide-y divide-[hsl(var(--border))]">
              {data.recentActivity.map((item) => (
                <div data-testid={`activity-item-${item.id}`} key={item.id} className="flex items-center gap-3 py-3 first:pt-1">
                  <div
                    className={`grid size-8 shrink-0 place-items-center rounded-lg ${
                      item.riskLevel === 'High'
                        ? 'bg-[hsl(var(--destructive)/.12)] text-[hsl(var(--destructive))]'
                        : item.riskLevel === 'Medium'
                        ? 'bg-[hsl(var(--chart-3)/.14)] text-[hsl(var(--chart-3))]'
                        : 'bg-[hsl(var(--primary)/.12)] text-[hsl(var(--primary))]'
                    }`}
                  >
                    <Activity size={15} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-bold">{item.description}</div>
                    <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">
                      {item.eventType} · {formatTime(item.timestamp)}
                    </div>
                  </div>
                  <RiskBadge risk={item.riskLevel} />
                </div>
              ))}
            </div>
          )}
        </Panel>

        <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-1">
          {/* Hybrid Encryption Plane Widget */}
          {encryption && (
            <Panel className="p-5">
              <div className="flex items-center justify-between">
                <SectionHead
                  eyebrow="Research Engine §3.3.1"
                  title="Layered Hybrid Encryption"
                  detail="AES-256-GCM + Random Perturbation Vector"
                />
                <Button
                  variant="quiet"
                  className="text-xs h-8"
                  loading={rotatingKey}
                  onClick={triggerKeyRotation}
                  title="Rotate Session Key"
                >
                  <RefreshCw size={12} /> Rotate Key
                </Button>
              </div>

              <div className="space-y-3 mt-2">
                <div className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3">
                  <div className="flex items-center gap-2 text-xs">
                    <KeyRound size={16} className="text-[hsl(var(--primary))]" />
                    <span className="font-semibold">Session Key Epoch #{encryption.keyRotationEpoch}</span>
                  </div>
                  <span className="mono text-xs text-[hsl(var(--primary))]">{encryption.sessionKeyFingerprint}••••</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg bg-[hsl(var(--muted)/.5)] p-2.5">
                    <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Perturbation Vectors</div>
                    <div className="mono mt-1 font-bold">{encryption.perturbationVectorsGenerated} generated</div>
                  </div>
                  <div className="rounded-lg bg-[hsl(var(--muted)/.5)] p-2.5">
                    <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Next Key Rotation</div>
                    <div className="mono mt-1 font-bold">{encryption.nextRotationInSeconds}s</div>
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {/* Threat Mix */}
          <Panel className="p-5">
            <SectionHead eyebrow="Distribution" title="Threat mix" />
            <div className="space-y-3">
              {Object.entries(data.threatDistribution).length ? (
                Object.entries(data.threatDistribution).map(([key, value], i) => (
                  <div key={key}>
                    <div className="mb-1.5 flex justify-between text-xs">
                      <span className="font-semibold">{key}</span>
                      <span className="mono text-[10px] text-[hsl(var(--muted-foreground))]">{value}</span>
                    </div>
                    <div className="h-2 rounded-full bg-[hsl(var(--muted))]">
                      <div
                        className={`h-full rounded-full ${distributionColors[i % distributionColors.length]}`}
                        style={{ width: `${Math.min(Number(value), 100)}%` }}
                      />
                    </div>
                  </div>
                ))
              ) : (
                <QueryState empty />
              )}
            </div>
          </Panel>

          {/* Privacy Posture Quick Card */}
          <Panel className="p-5">
            <SectionHead
              eyebrow="Control plane"
              title="Privacy posture"
              action={
                <Link href="/privacy" data-testid="link-review-privacy" className="text-[hsl(var(--primary))]">
                  <ArrowUpRight size={16} />
                </Link>
              }
            />
            <div className="flex items-end justify-between">
              <div>
                <div className="mono text-4xl font-medium tracking-[-.07em]">{data.privacyLevel}</div>
                <div className="mt-2 text-xs text-[hsl(var(--muted-foreground))]">{data.privacyStatus}</div>
              </div>
              <Database size={30} className="text-[hsl(var(--primary))]" />
            </div>
            <div className="mt-5 grid grid-cols-3 gap-1">
              {['Low', 'Medium', 'High'].map((level) => (
                <div
                  key={level}
                  className={`h-1.5 rounded-full ${level === data.privacyLevel ? 'bg-[hsl(var(--primary))]' : 'bg-[hsl(var(--muted))]'}`}
                />
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

export function PageLoading({ title }: { title: string }) {
  return (
    <div className="space-y-6" data-testid="page-loading">
      <div>
        <div className="h-3 w-36 animate-pulse rounded bg-[hsl(var(--muted))]" />
        <div className="mt-3 h-10 w-80 animate-pulse rounded bg-[hsl(var(--muted))]" />
        <p className="mt-3 text-sm text-[hsl(var(--muted-foreground))]">Loading {title.toLowerCase()} signals…</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 animate-pulse rounded-xl bg-[hsl(var(--muted))]" />
        ))}
      </div>
    </div>
  );
}