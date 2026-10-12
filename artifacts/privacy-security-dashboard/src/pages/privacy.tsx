import { useEffect, useState } from 'react';
import { Cpu, EyeOff, Fingerprint, Lock, Play, Radio, ShieldAlert, ShieldCheck, Sparkles, TrendingUp, type LucideIcon } from 'lucide-react';
import { useGetPrivacy, useUpdatePrivacy, getGetPrivacyQueryKey, getGetDashboardQueryKey } from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import { Badge, Button, Field, Panel, QueryState, SectionHead } from '@/components/ui-kit';
import { PageLoading } from '@/pages/dashboard';

interface DpTrainEpochResult {
  iteration: number;
  loss: number;
  accuracy: number;
  cumulativeEpsilon: number;
  membershipInferenceRisk: number;
  balanceScore: number;
  isBalanced: boolean;
  adaptedConfig?: {
    clippingThreshold: number;
    noiseMultiplier: number;
  };
  sampleGradients: {
    rawNormMean: number;
    clippedNormMean: number;
    noiseScale: number;
  };
}

interface DpBenchmark {
  epsilon: number;
  modelAccuracy: number;
  miaSuccessRate: number;
  trainingTimeGrowthPct: number;
  adversarialRobustness: number;
}

export function PrivacyPage() {
  const privacy = useGetPrivacy();
  const update = useUpdatePrivacy();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);

  // DP-SGD State
  const [clippingC, setClippingC] = useState('1.5');
  const [noiseSigma, setNoiseSigma] = useState('1.1');
  const [isTraining, setIsTraining] = useState(false);
  const [lastEpoch, setLastEpoch] = useState<DpTrainEpochResult | null>(null);
  const [benchmarks, setBenchmarks] = useState<DpBenchmark[]>([]);

  useEffect(() => {
    fetch('/api/privacy/dp-sgd/benchmarks')
      .then((r) => r.json())
      .then((b) => setBenchmarks(b))
      .catch((err) => console.error(err));
  }, []);

  const runDpSgdEpoch = async () => {
    setIsTraining(true);
    try {
      const res = await fetch('/api/privacy/dp-sgd/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clippingThreshold: Number(clippingC),
          noiseMultiplier: Number(noiseSigma),
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setLastEpoch(data);
        if (data.adaptedConfig) {
          setClippingC(String(data.adaptedConfig.clippingThreshold));
          setNoiseSigma(String(data.adaptedConfig.noiseMultiplier));
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsTraining(false);
    }
  };

  const data = privacy.data;
  if (privacy.isLoading) return <PageLoading title="privacy posture" />;
  if (privacy.isError || !data) return <QueryState error retry={() => privacy.refetch()} />;

  const level = selected ?? data.level;
  const previews: { label: string; value: string; icon: LucideIcon }[] = [
    { label: 'Email', value: data.maskedEmail, icon: EyeOff },
    { label: 'Username', value: data.maskedUsername, icon: Lock },
    { label: 'IP address', value: data.maskedIp, icon: Radio },
  ];

  const save = () =>
    update.mutate(
      { data: { level: level as 'Low' | 'Medium' | 'High' } },
      {
        onSuccess: (result) => {
          setSelected(result.level);
          queryClient.setQueryData(getGetPrivacyQueryKey(), result);
          queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        },
      },
    );

  return (
    <div className="animate-rise space-y-7">
      <div>
        <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
          Privacy plane / differential signals
        </div>
        <h1 className="text-3xl font-extrabold tracking-[-.055em]">Privacy Posture & AI DP-SGD</h1>
        <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
          Differentially Private SGD (DP-SGD), cumulative privacy budget tracking, and resistance against Membership Inference Attacks.
        </p>
      </div>

      {/* ADVANCED SECTION: AI Model DP-SGD Training Studio */}
      <Panel className="p-6 border-[hsl(var(--primary)/.35)] bg-[hsl(var(--card))]">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <SectionHead
            eyebrow="Research Engine §3.2"
            title="AI Model Differential Privacy Training Studio (DP-SGD)"
            detail="Per-sample gradient clipping g_i = g_i / max(1, ||g_i||_2 / C) and Gaussian noise injection g_hat = 1/L · Σg_i + N(0, σ²C²I)."
          />
          <Button loading={isTraining} onClick={runDpSgdEpoch} className="h-10 text-xs">
            <Play size={14} /> Execute DP-SGD Step
          </Button>
        </div>

        <div className="mt-4 grid gap-5 lg:grid-cols-[1fr_1.3fr]">
          {/* Controls & Configuration */}
          <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4 space-y-4">
            <div className="mono text-xs font-bold text-[hsl(var(--muted-foreground))]">
              Hyperparameter & Noise Configuration
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold block mb-1">Clipping Threshold C</label>
                <input
                  type="number"
                  step="0.1"
                  min="0.5"
                  max="5.0"
                  value={clippingC}
                  onChange={(e) => setClippingC(e.target.value)}
                  className="w-full h-9 rounded-lg border border-[hsl(var(--input))] bg-[hsl(var(--card))] px-3 text-xs"
                />
                <span className="text-[10px] text-[hsl(var(--muted-foreground))]">Norm bound for gradient clipping</span>
              </div>

              <div>
                <label className="text-xs font-semibold block mb-1">Noise Multiplier σ</label>
                <input
                  type="number"
                  step="0.1"
                  min="0.2"
                  max="3.0"
                  value={noiseSigma}
                  onChange={(e) => setNoiseSigma(e.target.value)}
                  className="w-full h-9 rounded-lg border border-[hsl(var(--input))] bg-[hsl(var(--card))] px-3 text-xs"
                />
                <span className="text-[10px] text-[hsl(var(--muted-foreground))]">Gaussian standard deviation factor</span>
              </div>
            </div>

            {lastEpoch ? (
              <div className="pt-3 border-t border-[hsl(var(--border))] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">Cumulative Privacy Loss (ε_t)</span>
                  <span className="mono text-base font-extrabold text-[hsl(var(--primary))]">
                    ε = {lastEpoch.cumulativeEpsilon}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">MIA Vulnerability (R)</span>
                  <span className="mono text-xs font-bold text-[hsl(var(--chart-3))]">
                    {Math.round(lastEpoch.membershipInferenceRisk * 100)}% Risk
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">Balance Score Ψ = λ1(1-A) + λ2·R</span>
                  <Badge tone={lastEpoch.isBalanced ? 'good' : 'warn'}>
                    Ψ = {lastEpoch.balanceScore} {lastEpoch.isBalanced ? '(Optimal)' : '(Adapting)'}
                  </Badge>
                </div>

                {lastEpoch.adaptedConfig && (
                  <div className="rounded-lg bg-[hsl(var(--primary)/.08)] border border-[hsl(var(--primary)/.2)] p-2.5 text-[11px] text-[hsl(var(--primary))]">
                    Balance scheduler adapted parameters: C → {lastEpoch.adaptedConfig.clippingThreshold}, σ → {lastEpoch.adaptedConfig.noiseMultiplier}
                  </div>
                )}
              </div>
            ) : (
              <div className="py-6 text-center text-xs text-[hsl(var(--muted-foreground))]">
                Click &quot;Execute DP-SGD Step&quot; to perform an in-flight differentially private gradient update.
              </div>
            )}
          </div>

          {/* Real-time Gradient Metrics & Norms */}
          <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
            <div className="mono text-xs font-bold text-[hsl(var(--muted-foreground))] mb-3">
              Differential Privacy Gradient Metrics (Iteration #{lastEpoch?.iteration ?? 0})
            </div>

            {lastEpoch ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                    <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Model Accuracy (A)</div>
                    <div className="mono mt-1 text-base font-bold text-emerald-400">
                      {Math.round(lastEpoch.accuracy * 100)}%
                    </div>
                  </div>
                  <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                    <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Cross-Entropy Loss</div>
                    <div className="mono mt-1 text-base font-bold text-amber-400">{lastEpoch.loss}</div>
                  </div>
                  <div className="rounded-lg border border-[hsl(var(--border))] p-2.5">
                    <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Injected Noise Scale</div>
                    <div className="mono mt-1 text-base font-bold text-[hsl(var(--primary))]">
                      ±{lastEpoch.sampleGradients.noiseScale}
                    </div>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span>Raw Gradient Norm (Pre-Clipping)</span>
                      <span className="mono">{lastEpoch.sampleGradients.rawNormMean}</span>
                    </div>
                    <div className="h-2 rounded-full bg-[hsl(var(--muted))]">
                      <div
                        className="h-full rounded-full bg-red-400"
                        style={{ width: `${Math.min(100, lastEpoch.sampleGradients.rawNormMean * 35)}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span>Clipped Gradient Norm (Bounded by C = {clippingC})</span>
                      <span className="mono text-[hsl(var(--primary))]">{lastEpoch.sampleGradients.clippedNormMean}</span>
                    </div>
                    <div className="h-2 rounded-full bg-[hsl(var(--muted))]">
                      <div
                        className="h-full rounded-full bg-[hsl(var(--primary))]"
                        style={{ width: `${Math.min(100, lastEpoch.sampleGradients.clippedNormMean * 35)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-10 text-center text-xs text-[hsl(var(--muted-foreground))]">
                No active gradient batch. Start training to view clipping and noise dissipation.
              </div>
            )}
          </div>
        </div>

        {/* Figure 4 Benchmark Table from Paper */}
        {benchmarks.length > 0 && (
          <div className="mt-6 pt-5 border-t border-[hsl(var(--border))]">
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp size={16} className="text-[hsl(var(--primary))]" />
              <span className="text-xs font-bold">Research Benchmark: Privacy Budget vs. MIA Risk & Accuracy (Paper Fig. 4)</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[hsl(var(--muted)/.6)] text-[10px] uppercase mono text-[hsl(var(--muted-foreground))]">
                  <tr>
                    <th className="py-2 px-3">Privacy Budget (ε)</th>
                    <th className="py-2 px-3">Model Accuracy (%)</th>
                    <th className="py-2 px-3">MIA Success Rate (%)</th>
                    <th className="py-2 px-3">Training Overhead (%)</th>
                    <th className="py-2 px-3">Adversarial Robustness (%)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[hsl(var(--border))] mono">
                  {benchmarks.map((b) => (
                    <tr key={b.epsilon} className="hover:bg-[hsl(var(--muted)/.3)]">
                      <td className="py-2 px-3 font-bold text-[hsl(var(--primary))]">ε = {b.epsilon}</td>
                      <td className="py-2 px-3 text-emerald-400">{b.modelAccuracy}%</td>
                      <td className="py-2 px-3 text-red-400">{b.miaSuccessRate}%</td>
                      <td className="py-2 px-3">+{b.trainingTimeGrowthPct}%</td>
                      <td className="py-2 px-3 text-blue-400">{b.adversarialRobustness}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Panel>

      {/* Existing Privacy Controls Grid */}
      <div className="grid gap-5 xl:grid-cols-[.75fr_1.25fr]">
        <Panel className="command-grid relative overflow-hidden p-6">
          <div className="absolute right-6 top-6 grid size-11 place-items-center rounded-xl bg-[hsl(var(--primary)/.13)] text-[hsl(var(--primary))]">
            <Fingerprint size={22} />
          </div>
          <SectionHead eyebrow="Active setting" title="Privacy level" detail={data.status} />
          <div className="mt-9">
            <div className="mono text-6xl font-medium tracking-[-.09em]">{level}</div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-[hsl(var(--muted))]">
              <div
                className={`h-full rounded-full transition-all ${
                  level === 'High' ? 'w-full' : level === 'Medium' ? 'w-2/3' : 'w-1/3'
                } bg-[hsl(var(--primary))]`}
              />
            </div>
            <div className="mt-2 flex justify-between text-[10px] text-[hsl(var(--muted-foreground))]">
              <span>Less noise</span>
              <span>More private</span>
            </div>
          </div>
          <div className="mt-8 space-y-2">
            {(['Low', 'Medium', 'High'] as const).map((item) => (
              <button
                key={item}
                data-testid={`button-privacy-${item.toLowerCase()}`}
                onClick={() => setSelected(item)}
                className={`flex w-full items-center justify-between rounded-lg border px-3 py-3 text-left transition ${
                  level === item
                    ? 'border-[hsl(var(--primary)/.6)] bg-[hsl(var(--primary)/.08)]'
                    : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--muted))]'
                }`}
              >
                <span className="flex items-center gap-2 text-xs font-bold">
                  <span
                    className={`size-2 rounded-full ${
                      item === 'High'
                        ? 'bg-[hsl(var(--primary))]'
                        : item === 'Medium'
                        ? 'bg-[hsl(var(--chart-3))]'
                        : 'bg-[hsl(var(--muted-foreground))]'
                    }`}
                  />
                  {item}
                </span>
                {level === item && <ShieldCheck size={15} className="text-[hsl(var(--primary))]" />}
              </button>
            ))}
          </div>
          <Button data-testid="button-save-privacy" onClick={save} loading={update.isPending} className="mt-5 w-full">
            Save privacy level
          </Button>
          {update.isError && (
            <p data-testid="status-privacy-error" className="mt-2 text-xs text-[hsl(var(--destructive))]">
              Privacy level could not be updated.
            </p>
          )}
        </Panel>

        <Panel className="p-6">
          <SectionHead
            eyebrow="Privacy preview"
            title="What leaves the room"
            detail="Examples are transformed before they reach downstream analysis."
          />
          <div className="grid gap-3 sm:grid-cols-3">
            {previews.map(({ label, value, icon: Icon }) => (
              <div key={label} className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
                <div className="mb-7 flex items-center justify-between text-[hsl(var(--muted-foreground))]">
                  <span className="text-xs font-bold">{label}</span>
                  <Icon size={15} />
                </div>
                <div className="mono truncate text-sm font-medium">{value}</div>
                <div className="mt-2 text-[10px] text-[hsl(var(--muted-foreground))]">masked example</div>
              </div>
            ))}
          </div>

          <div className="mt-7 border-t border-[hsl(var(--border))] pt-5">
            <div className="mb-4 flex items-center gap-2">
              <ShieldCheck size={15} className="text-[hsl(var(--primary))]" />
              <span className="text-xs font-bold">Laplace Noise Aggregation</span>
              <Badge tone="info">ε {data.epsilon}</Badge>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <StatCompare label="Threats" raw={data.rawThreats} privateValue={data.privateThreats} />
              <StatCompare label="Average trust" raw={data.rawAverageTrust} privateValue={data.privateAverageTrust} />
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function StatCompare({ label, raw, privateValue }: { label: string; raw: number; privateValue: number }) {
  return (
    <div className="rounded-lg bg-[hsl(var(--muted)/.6)] p-3">
      <div className="mb-3 text-[10px] font-bold uppercase tracking-[.12em] text-[hsl(var(--muted-foreground))]">
        {label}
      </div>
      <div className="flex items-end justify-between">
        <div>
          <div className="mono text-lg">{privateValue}</div>
          <div className="text-[10px] text-[hsl(var(--muted-foreground))]">private view</div>
        </div>
        <div className="text-right">
          <div className="mono text-sm text-[hsl(var(--muted-foreground))]">{raw}</div>
          <div className="text-[10px] text-[hsl(var(--muted-foreground))]">raw reference</div>
        </div>
      </div>
    </div>
  );
}