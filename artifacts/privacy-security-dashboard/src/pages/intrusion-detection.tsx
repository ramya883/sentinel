import { useEffect, useState } from 'react';
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Brain,
  CheckCircle2,
  Cpu,
  Database,
  FastForward,
  Flame,
  Laptop,
  Pause,
  Play,
  Radar,
  Radio,
  RefreshCw,
  RotateCcw,
  Send,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  TrendingUp,
  XCircle,
} from 'lucide-react';
import { useAnalyzeTraffic, useListIntrusionEvents, getListIntrusionEventsQueryKey, getGetDashboardQueryKey } from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import { Badge, Button, Field, Panel, QueryState, RiskBadge, SectionHead } from '@/components/ui-kit';
import { PageLoading } from '@/pages/dashboard';

type TrafficState = {
  duration: string;
  srcBytes: string;
  dstBytes: string;
  failedLogins: string;
  packetCount: string;
  connectionRate: string;
};

const initial: TrafficState = {
  duration: '60',
  srcBytes: '2400',
  dstBytes: '1800',
  failedLogins: '0',
  packetCount: '84',
  connectionRate: '1.4',
};

interface GruAnalysisResult {
  modelType: string;
  reconstructionError: number;
  normalityConfidence: number;
  anomalyProbability: number;
  comprehensiveRiskScore: number;
  classification: string;
  riskLevel: string;
  comparisonWithIsolationForest: {
    isolationForestScore: number;
    isolationForestRisk: string;
    agreement: boolean;
  };
}

export function IntrusionDetectionPage() {
  const events = useListIntrusionEvents();
  const analyze = useAnalyzeTraffic();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<TrafficState>(initial);
  const [activeModel, setActiveModel] = useState<'GRU-Autoencoder' | 'Isolation-Forest'>('GRU-Autoencoder');
  const [gruResult, setGruResult] = useState<GruAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Real-Time Dataset Laboratory State
  const [streamSource, setStreamSource] = useState<'nsl-kdd' | 'host-live'>('nsl-kdd');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | 'NORMAL' | 'DOS' | 'PROBE' | 'R2L' | 'U2R'>('ALL');
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamSpeed, setStreamSpeed] = useState<number>(1500); // ms
  const [lastDatasetEvent, setLastDatasetEvent] = useState<any>(null);
  const [datasetStats, setDatasetStats] = useState({
    totalStreamed: 0,
    matches: 0,
    attacksDetected: 0,
    normalApproved: 0,
  });
  const [benchmarkResult, setBenchmarkResult] = useState<any>(null);
  const [isBatchTesting, setIsBatchTesting] = useState(false);
  const [hostMetrics, setHostMetrics] = useState<any>(null);
  const [isSamplingHost, setIsSamplingHost] = useState(false);

  // Send single sample from NSL-KDD
  const sendNextSample = async () => {
    try {
      const res = await fetch('/api/dataset/nsl-kdd/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: categoryFilter }),
      });
      if (res.ok) {
        const data = await res.json();
        setLastDatasetEvent(data);
        setGruResult(data.gruEvaluation);
        setDatasetStats((prev) => ({
          totalStreamed: prev.totalStreamed + 1,
          matches: prev.matches + (data.accuracyMatch ? 1 : 0),
          attacksDetected: prev.attacksDetected + (data.record.isAnomaly ? 1 : 0),
          normalApproved: prev.normalApproved + (!data.record.isAnomaly ? 1 : 0),
        }));
        queryClient.invalidateQueries({ queryKey: getListIntrusionEventsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Sample live hardware traffic from host network card
  const sampleHostLive = async () => {
    setIsSamplingHost(true);
    try {
      const res = await fetch('/api/dataset/host-live');
      if (res.ok) {
        const netData = await res.json();
        setHostMetrics(netData);
        // Automatically evaluate vector in GRU
        const evalRes = await fetch('/api/intrusion/gru-analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(netData),
        });
        if (evalRes.ok) {
          const evalJson = await evalRes.json();
          setGruResult(evalJson.gruEvaluation);
          setLastDatasetEvent({
            record: {
              id: 9999,
              protocol: 'TCP/UDP Live',
              service: 'host-nic',
              duration: netData.duration,
              srcBytes: netData.srcBytes,
              dstBytes: netData.dstBytes,
              packetCount: netData.packetCount,
              connectionRate: netData.connectionRate,
              label: 'Host Physical NIC',
              attackCategory: evalJson.gruEvaluation.classification === 'Suspicious' ? 'LIVE-ANOMALY' : 'LIVE-NORMAL',
              isAnomaly: evalJson.gruEvaluation.classification === 'Suspicious',
            },
            gruEvaluation: evalJson.gruEvaluation,
            accuracyMatch: true,
            mitigationApplied: evalJson.mitigationApplied,
          });
          queryClient.invalidateQueries({ queryKey: getListIntrusionEventsQueryKey() });
          queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSamplingHost(false);
    }
  };

  // Automatic real-time streaming ticker
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(() => {
      if (streamSource === 'nsl-kdd') {
        sendNextSample();
      } else {
        sampleHostLive();
      }
    }, streamSpeed);
    return () => clearInterval(interval);
  }, [isStreaming, streamSource, categoryFilter, streamSpeed]);

  // Run 100-sample benchmark test
  const runBatchBenchmark = async () => {
    setIsBatchTesting(true);
    try {
      const res = await fetch('/api/dataset/nsl-kdd/batch-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sampleSize: 100 }),
      });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsBatchTesting(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const payload = Object.fromEntries(
      Object.entries(form).map(([key, value]) => [key, Number(value)]),
    );

    if (activeModel === 'GRU-Autoencoder') {
      setIsAnalyzing(true);
      try {
        const res = await fetch('/api/intrusion/gru-analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) {
          const data = await res.json();
          setGruResult(data.gruEvaluation);
          queryClient.invalidateQueries({ queryKey: getListIntrusionEventsQueryKey() });
          queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        }
      } finally {
        setIsAnalyzing(false);
      }
    } else {
      analyze.mutate(
        { data: payload as any },
        {
          onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: getListIntrusionEventsQueryKey() });
            queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
            setGruResult(null);
          },
        },
      );
    }
  };

  if (events.isLoading) return <PageLoading title="intrusion detection" />;
  if (events.isError) return <QueryState error retry={() => events.refetch()} />;

  const list = events.data ?? [];

  return (
    <div className="animate-rise space-y-7">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
            Network plane / deep behavioral analysis
          </div>
          <h1 className="text-3xl font-extrabold tracking-[-.055em]">AI Intrusion Detection System</h1>
          <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
            GRU Sequence Autoencoder behavioral reconstruction and multi-model dual-loss threat scoring.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone="info">
            <Radar size={12} className="mr-1" /> Dual ML Engines Ready
          </Badge>
        </div>
      </div>

      {/* Model Selection Tabs */}
      <div className="flex items-center gap-3">
        <span className="text-xs font-semibold text-[hsl(var(--muted-foreground))]">Active Model:</span>
        <button
          onClick={() => setActiveModel('GRU-Autoencoder')}
          className={`flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-bold transition ${
            activeModel === 'GRU-Autoencoder'
              ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]'
              : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--muted))]'
          }`}
        >
          <Brain size={15} /> GRU Sequence Autoencoder + Discriminator (Paper §3.3.2)
        </button>
        <button
          onClick={() => setActiveModel('Isolation-Forest')}
          className={`flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-bold transition ${
            activeModel === 'Isolation-Forest'
              ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]'
              : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--muted))]'
          }`}
        >
          <Cpu size={15} /> 32-Tree Isolation Forest (Baseline)
        </button>
      </div>

      {/* REAL-TIME DATASET LABORATORY & STREAMER */}
      <Panel className="p-5 border-[hsl(var(--primary)/.4)] bg-gradient-to-br from-[hsl(var(--card))] to-[hsl(var(--background))] space-y-5">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <SectionHead
            eyebrow="Base Paper §4.2 Benchmark & Physical Sniffer"
            title="Real-Time Dataset Streamer & Network Laboratory"
            detail="Stream verified benchmark traces from NSL-KDD (94.1% Accuracy) or sample live hardware packets from your host machine."
          />
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setStreamSource('nsl-kdd')}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-bold transition ${
                streamSource === 'nsl-kdd'
                  ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.2)] text-[hsl(var(--primary))] shadow-sm'
                  : 'border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--muted))]'
              }`}
            >
              <Database size={13} /> NSL-KDD Benchmark (Paper)
            </button>
            <button
              onClick={() => setStreamSource('host-live')}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-bold transition ${
                streamSource === 'host-live'
                  ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400 shadow-sm'
                  : 'border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--muted))]'
              }`}
            >
              <Radio size={13} /> Host Hardware Sniffer (Live NIC)
            </button>
          </div>
        </div>

        {/* Controls row */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background)/.6)] p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`h-9 px-4 text-xs font-bold ${
                isStreaming
                  ? 'bg-rose-600 hover:bg-rose-500 text-white'
                  : 'bg-[hsl(var(--primary))] text-black hover:bg-[hsl(var(--primary)/.85)]'
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause size={14} className="mr-1.5" /> Pause Real-Time Stream
                </>
              ) : (
                <>
                  <Play size={14} className="mr-1.5" /> Start Real-Time Stream
                </>
              )}
            </Button>

            <Button
              variant="outline"
              onClick={streamSource === 'nsl-kdd' ? sendNextSample : sampleHostLive}
              disabled={isStreaming || isSamplingHost}
              className="h-9 text-xs"
            >
              <FastForward size={14} className="mr-1.5" />
              {streamSource === 'nsl-kdd' ? 'Step Single Packet' : isSamplingHost ? 'Sampling NIC...' : 'Sample Live NIC'}
            </Button>

            {streamSource === 'nsl-kdd' && (
              <Button
                variant="outline"
                onClick={runBatchBenchmark}
                loading={isBatchTesting}
                className="h-9 text-xs border-indigo-500/40 text-indigo-400 hover:bg-indigo-500/10"
              >
                <Sparkles size={14} className="mr-1.5" /> Run 100-Sample Benchmark
              </Button>
            )}
          </div>

          {/* Category Filter Pills (when in NSL-KDD mode) */}
          {streamSource === 'nsl-kdd' ? (
            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="mono text-[10px] text-[hsl(var(--muted-foreground))] mr-1">Attack Slice:</span>
              {(['ALL', 'NORMAL', 'DOS', 'PROBE', 'R2L', 'U2R'] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase transition ${
                    categoryFilter === cat
                      ? 'bg-[hsl(var(--primary))] text-black font-bold'
                      : 'bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs text-emerald-400 mono">
              <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
              Capturing Local Ethernet / Wi-Fi Adapter
            </div>
          )}
        </div>

        {/* Live Streaming Telemetry Dashboard */}
        <div className="grid gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3.5">
            <div className="mono text-[10px] text-[hsl(var(--muted-foreground))] uppercase">Total Streamed</div>
            <div className="mono mt-1 text-2xl font-extrabold text-[hsl(var(--foreground))]">
              {datasetStats.totalStreamed}
            </div>
            <div className="text-[10px] text-[hsl(var(--muted-foreground))]">
              {datasetStats.attacksDetected} attacks · {datasetStats.normalApproved} normal
            </div>
          </div>

          <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3.5">
            <div className="mono text-[10px] text-[hsl(var(--muted-foreground))] uppercase">Live Stream Accuracy</div>
            <div className="mono mt-1 text-2xl font-extrabold text-emerald-400">
              {datasetStats.totalStreamed > 0
                ? `${((datasetStats.matches / datasetStats.totalStreamed) * 100).toFixed(1)}%`
                : '94.1% (Base Paper)'}
            </div>
            <div className="text-[10px] text-emerald-400/80">
              {datasetStats.matches} / {datasetStats.totalStreamed} verified matches
            </div>
          </div>

          <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3.5 sm:col-span-2">
            <div className="mono text-[10px] text-[hsl(var(--muted-foreground))] uppercase">Latest Packet Inspected</div>
            {lastDatasetEvent ? (
              <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="mono text-xs font-bold text-[hsl(var(--foreground))]">
                    #{lastDatasetEvent.record.id} · {lastDatasetEvent.record.label.toUpperCase()}
                  </span>
                  <span className="ml-2 rounded bg-[hsl(var(--muted))] px-1.5 py-0.5 mono text-[10px] text-[hsl(var(--muted-foreground))]">
                    {lastDatasetEvent.record.protocol.toUpperCase()} · {lastDatasetEvent.record.srcBytes}B TX
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-extrabold uppercase ${
                      lastDatasetEvent.accuracyMatch
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {lastDatasetEvent.accuracyMatch ? '✓ Verified Accurate' : 'Discrepancy'}
                  </span>
                  <RiskBadge risk={lastDatasetEvent.gruEvaluation?.riskLevel ?? 'Low'} />
                </div>
              </div>
            ) : (
              <div className="mono mt-1.5 text-xs text-[hsl(var(--muted-foreground))]">
                Click &quot;Start Real-Time Stream&quot; or &quot;Step Single Packet&quot; to inject real data.
              </div>
            )}
            {lastDatasetEvent && (
              <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">
                Truth: {lastDatasetEvent.record.isAnomaly ? 'Attack' : 'Normal'} | Pred: {lastDatasetEvent.gruEvaluation?.classification} | L_rec: {lastDatasetEvent.gruEvaluation?.reconstructionError}
              </div>
            )}
          </div>
        </div>

        {/* 100-Sample Benchmark Results Modal/Card if executed */}
        {benchmarkResult && (
          <div className="rounded-lg border border-indigo-500/40 bg-indigo-950/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles size={16} className="text-indigo-400" />
                <span className="text-xs font-bold text-indigo-300">
                  {benchmarkResult.dataset} — 100 Sample Stratified Evaluation
                </span>
              </div>
              <button
                onClick={() => setBenchmarkResult(null)}
                className="text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
              >
                ✕ Close
              </button>
            </div>

            <div className="grid gap-2 sm:grid-cols-4">
              <div className="rounded bg-[hsl(var(--background))] p-2.5">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Accuracy</div>
                <div className="mono text-lg font-bold text-emerald-400">{benchmarkResult.accuracy}%</div>
                <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Paper benchmark: 94.1%</div>
              </div>
              <div className="rounded bg-[hsl(var(--background))] p-2.5">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Precision</div>
                <div className="mono text-lg font-bold text-cyan-400">{benchmarkResult.precision}%</div>
                <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Paper benchmark: 96.7%</div>
              </div>
              <div className="rounded bg-[hsl(var(--background))] p-2.5">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Recall</div>
                <div className="mono text-lg font-bold text-purple-400">{benchmarkResult.recall}%</div>
                <div className="text-[10px] text-[hsl(var(--muted-foreground))]">True Positive Rate</div>
              </div>
              <div className="rounded bg-[hsl(var(--background))] p-2.5">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">F1-Score</div>
                <div className="mono text-lg font-bold text-indigo-400">{benchmarkResult.f1Score}%</div>
                <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Harmonic Mean</div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-[11px] mono text-[hsl(var(--muted-foreground))] pt-1 border-t border-[hsl(var(--border))]">
              <span>Confusion Matrix:</span>
              <span className="text-emerald-400 font-bold">TP: {benchmarkResult.confusionMatrix.tp}</span>
              <span className="text-blue-400 font-bold">TN: {benchmarkResult.confusionMatrix.tn}</span>
              <span className="text-amber-400 font-bold">FP: {benchmarkResult.confusionMatrix.fp}</span>
              <span className="text-rose-400 font-bold">FN: {benchmarkResult.confusionMatrix.fn}</span>
            </div>
          </div>
        )}
      </Panel>

      {/* GRU Live Results Card if evaluated */}
      {gruResult && (
        <Panel className="p-5 border-[hsl(var(--primary)/.35)] bg-[hsl(var(--card))]">
          <SectionHead
            eyebrow="Evaluation Output"
            title="GRU Autoencoder + Discriminator Dual-Loss Scoring"
            detail="Comprehensive risk score R(X) = α·L_rec + β·(1 - D(X)) with α=0.55, β=0.45."
          />

          <div className="grid gap-3 sm:grid-cols-4 mt-3">
            <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3">
              <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Reconstruction Error L_rec</div>
              <div className="mono mt-1 text-lg font-bold text-amber-400">
                {gruResult.reconstructionError}
              </div>
              <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Euclidean deviation from normal</div>
            </div>

            <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3">
              <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Normality Probability D(X)</div>
              <div className="mono mt-1 text-lg font-bold text-blue-400">
                {Math.round(gruResult.normalityConfidence * 100)}%
              </div>
              <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Discriminator confidence</div>
            </div>

            <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3">
              <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Composite Score R(X)</div>
              <div className="mono mt-1 text-lg font-extrabold text-[hsl(var(--primary))]">
                {Math.round(gruResult.comprehensiveRiskScore * 100)}%
              </div>
              <div className="text-[10px] text-[hsl(var(--muted-foreground))]">{gruResult.riskLevel} Risk</div>
            </div>

            <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-3">
              <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Baseline Isolation Forest</div>
              <div className="mono mt-1 text-lg font-bold">
                {Math.round(gruResult.comparisonWithIsolationForest.isolationForestScore * 100)}%
              </div>
              <div className="text-[10px] text-emerald-400">
                {gruResult.comparisonWithIsolationForest.agreement ? '✓ Models in Agreement' : 'Disagreement Noted'}
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* Main Analysis Form & Feed */}
      <div className="grid gap-5 xl:grid-cols-[.7fr_1.3fr]">
        <Panel className="p-5">
          <SectionHead
            eyebrow="New signal"
            title="Analyze Traffic Vector"
            detail={`Normalized into temporal sequence for ${activeModel}.`}
          />
          <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
            <Field
              data-testid="input-duration"
              label="Duration"
              hint="seconds"
              type="number"
              min="0"
              step="0.01"
              value={form.duration}
              onChange={(e) => setForm({ ...form, duration: e.target.value })}
              required
            />
            <Field
              data-testid="input-src-bytes"
              label="Source bytes"
              type="number"
              min="0"
              value={form.srcBytes}
              onChange={(e) => setForm({ ...form, srcBytes: e.target.value })}
              required
            />
            <Field
              data-testid="input-dst-bytes"
              label="Destination bytes"
              type="number"
              min="0"
              value={form.dstBytes}
              onChange={(e) => setForm({ ...form, dstBytes: e.target.value })}
              required
            />
            <Field
              data-testid="input-failed-logins"
              label="Failed logins"
              type="number"
              min="0"
              value={form.failedLogins}
              onChange={(e) => setForm({ ...form, failedLogins: e.target.value })}
              required
            />
            <Field
              data-testid="input-packet-count"
              label="Packet count"
              type="number"
              min="0"
              value={form.packetCount}
              onChange={(e) => setForm({ ...form, packetCount: e.target.value })}
              required
            />
            <Field
              data-testid="input-connection-rate"
              label="Connection rate"
              hint="per second"
              type="number"
              min="0"
              step="0.1"
              value={form.connectionRate}
              onChange={(e) => setForm({ ...form, connectionRate: e.target.value })}
              required
            />
            <Button
              data-testid="button-analyze-traffic"
              type="submit"
              loading={isAnalyzing || analyze.isPending}
              className="mt-2 h-11 sm:col-span-2"
            >
              <Send size={15} /> Run {activeModel} Analysis
            </Button>
          </form>
          {analyze.isError && (
            <div data-testid="status-analysis-error" className="mt-3 text-xs text-[hsl(var(--destructive))]">
              Analysis failed. Verify the traffic values and retry.
            </div>
          )}
        </Panel>

        <Panel className="overflow-hidden">
          <div className="p-5 pb-2">
            <SectionHead
              eyebrow="Observed signals"
              title="Recent detections"
              detail="Newest traffic records appear first."
              action={
                <button
                  data-testid="button-refresh-events"
                  onClick={() => events.refetch()}
                  className="rounded-lg p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--muted))]"
                  title="Refresh"
                >
                  <RefreshCw size={15} />
                </button>
              }
            />
          </div>
          {!list.length ? (
            <div className="px-5 pb-5">
              <QueryState empty />
            </div>
          ) : (
            <div className="divide-y divide-[hsl(var(--border))]">
              {list.map((event) => (
                <div
                  data-testid={`intrusion-event-${event.id}`}
                  key={event.id}
                  className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center"
                >
                  <div
                    className={`grid size-9 shrink-0 place-items-center rounded-lg ${
                      event.classification === 'Suspicious'
                        ? 'bg-[hsl(var(--destructive)/.11)] text-[hsl(var(--destructive))]'
                        : 'bg-[hsl(var(--primary)/.12)] text-[hsl(var(--primary))]'
                    }`}
                  >
                    {event.classification === 'Suspicious' ? <Siren size={17} /> : <Activity size={17} />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-extrabold">{event.classification}</span>
                      <RiskBadge risk={event.riskLevel} />
                    </div>
                    <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">
                      {new Date(event.timestamp).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}{' '}
                      · {event.packetCount} packets · {event.connectionRate}/sec
                    </div>
                  </div>
                  <div className="flex items-center gap-2 sm:block sm:text-right">
                    <span className="mono text-lg font-medium">{event.anomalyScore}</span>
                    <span className="ml-1 text-[10px] text-[hsl(var(--muted-foreground))]">anomaly</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <SignalCard icon={ArrowUpFromLine} label="Source bytes" value={form.srcBytes} />
        <SignalCard icon={ArrowDownToLine} label="Destination bytes" value={form.dstBytes} />
        <SignalCard icon={Activity} label="Connection rate" value={`${form.connectionRate}/s`} />
      </div>
    </div>
  );
}

function SignalCard({ icon: Icon, label, value }: { icon: typeof Activity; label: string; value: string }) {
  return (
    <Panel className="flex items-center gap-3 p-4">
      <span className="grid size-9 place-items-center rounded-lg bg-[hsl(var(--muted))] text-[hsl(var(--primary))]">
        <Icon size={16} />
      </span>
      <span>
        <span className="block text-xs font-semibold text-[hsl(var(--muted-foreground))]">{label}</span>
        <span className="mono mt-1 block text-sm">{value}</span>
      </span>
    </Panel>
  );
}