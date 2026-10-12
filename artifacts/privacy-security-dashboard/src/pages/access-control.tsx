import { useEffect, useState } from 'react';
import { CheckCircle2, ChevronRight, Fingerprint, Laptop, MapPin, MoreHorizontal, Search, Shield, ShieldCheck, UserRound, UsersRound, XCircle, Zap } from 'lucide-react';
import { useListUsers, useUpdateUserRole, getListUsersQueryKey, getGetDashboardQueryKey } from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import { Badge, Button, Panel, QueryState, RiskBadge, SectionHead, SelectField } from '@/components/ui-kit';
import { PageLoading } from '@/pages/dashboard';

interface ZeroTrustResult {
  overallTrust: number;
  decision: 'Grant' | 'StepUpMFA' | 'Deny';
  components: {
    userReputation: number;
    deviceStability: number;
    contextSensitivity: number;
    alpha: number;
    beta: number;
    gamma: number;
  };
  contextBreakdown: {
    spatialDeviation: number;
    temporalDeviation: number;
    resourceSensitivityScore: number;
  };
  deviceFingerprint: {
    pcaVector: number[];
    fingerprintHash: string;
    isRecognized: boolean;
  };
  abacRulesChecked: Array<{ rule: string; passed: boolean }>;
}

export function AccessControlPage() {
  const users = useListUsers();
  const updateRole = useUpdateUserRole();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [selectedSensitivity, setSelectedSensitivity] = useState<'Internal' | 'Confidential' | 'Critical'>('Confidential');
  const [ztAssessment, setZtAssessment] = useState<ZeroTrustResult | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  const fetchZeroTrust = async (sensitivity = selectedSensitivity) => {
    setEvaluating(true);
    try {
      const res = await fetch('/api/zero-trust/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resourceSensitivity: sensitivity }),
      });
      if (res.ok) {
        setZtAssessment(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setEvaluating(false);
    }
  };

  useEffect(() => {
    fetchZeroTrust('Confidential');
  }, []);

  const data = users.data ?? [];
  const visible = data.filter((user) =>
    `${user.username} ${user.maskedEmail} ${user.role}`.toLowerCase().includes(search.toLowerCase()),
  );

  const roleChange = (id: number, role: string) =>
    updateRole.mutate(
      { id, data: { role: role as 'Admin' | 'Analyst' | 'User' } },
      {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
          queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        },
      },
    );

  if (users.isLoading) return <PageLoading title="access control" />;
  if (users.isError) return <QueryState error retry={() => users.refetch()} />;

  return (
    <div className="animate-rise space-y-7">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
            Identity plane / fine-grained access
          </div>
          <h1 className="text-3xl font-extrabold tracking-[-.055em]">Access Control & Zero-Trust</h1>
          <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
            PCA device fingerprinting, multi-dimensional trust formulas, and ABAC policy constraints.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
          <UsersRound size={15} /> {data.length} identities
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <MiniStat icon={Shield} label="Trusted" value={data.filter((u) => u.trustScore >= 80).length} color="text-[hsl(var(--primary))]" />
        <MiniStat icon={UserRound} label="In review" value={data.filter((u) => u.status === 'Review').length} color="text-[hsl(var(--chart-3))]" />
        <MiniStat icon={Laptop} label="Known devices" value={data.filter((u) => u.knownDevice).length} color="text-[hsl(var(--chart-4))]" />
      </div>

      {/* ADVANCED SECTION: Zero-Trust Dynamic Trust Model T(u, d, t) = α·Su + β·Sd + γ·At */}
      {ztAssessment && (
        <Panel className="p-6 border-[hsl(var(--primary)/.35)] bg-[hsl(var(--card))]">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <SectionHead
              eyebrow="Research Engine §3.1"
              title="Mathematical Zero-Trust Engine & PCA Device Fingerprinting"
              detail="Trust formulation T(u, d, t) = α·Su + β·Sd + γ·At fused with XACML / ABAC decision engine δ(p, c) ∈ {0, 1}."
            />
            <div className="flex items-center gap-2">
              <span className="text-xs text-[hsl(var(--muted-foreground))]">Resource:</span>
              {(['Internal', 'Confidential', 'Critical'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => {
                    setSelectedSensitivity(lvl);
                    fetchZeroTrust(lvl);
                  }}
                  className={`rounded-lg px-2.5 py-1 text-xs font-bold border transition ${
                    selectedSensitivity === lvl
                      ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]'
                      : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--muted))]'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 grid gap-5 lg:grid-cols-[1fr_1.3fr]">
            {/* Dynamic Trust Score Box */}
            <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="mono text-[10px] uppercase text-[hsl(var(--muted-foreground))]">
                    Synthesized Trust Score T(u, d, t)
                  </div>
                  <div className="mono mt-1 text-4xl font-extrabold text-[hsl(var(--primary))]">
                    {ztAssessment.overallTrust}
                    <span className="text-xs font-normal text-[hsl(var(--muted-foreground))]"> / 100</span>
                  </div>
                </div>
                <Badge
                  tone={
                    ztAssessment.decision === 'Grant'
                      ? 'good'
                      : ztAssessment.decision === 'StepUpMFA'
                      ? 'warn'
                      : 'danger'
                  }
                >
                  Policy: {ztAssessment.decision.toUpperCase()}
                </Badge>
              </div>

              {/* 3 Component Breakdown */}
              <div className="mt-5 space-y-3">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-semibold">User Reputation (α·Su = 0.45 · {ztAssessment.components.userReputation})</span>
                    <span className="mono">{Math.round(ztAssessment.components.alpha * ztAssessment.components.userReputation)}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[hsl(var(--muted))]">
                    <div className="h-full rounded-full bg-[hsl(var(--primary))]" style={{ width: `${ztAssessment.components.userReputation}%` }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-semibold">Device Stability (β·Sd = 0.25 · {ztAssessment.components.deviceStability})</span>
                    <span className="mono">{Math.round(ztAssessment.components.beta * ztAssessment.components.deviceStability)}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[hsl(var(--muted))]">
                    <div className="h-full rounded-full bg-[hsl(var(--chart-3))]" style={{ width: `${ztAssessment.components.deviceStability}%` }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-semibold">Context Sensitivity (γ·At = 0.30 · {ztAssessment.components.contextSensitivity})</span>
                    <span className="mono">{Math.round(ztAssessment.components.gamma * ztAssessment.components.contextSensitivity)}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[hsl(var(--muted))]">
                    <div className="h-full rounded-full bg-[hsl(var(--chart-4))]" style={{ width: `${ztAssessment.components.contextSensitivity}%` }} />
                  </div>
                </div>
              </div>

              {/* PCA Device Fingerprint Hash */}
              <div className="mt-5 pt-3 border-t border-[hsl(var(--border))] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5">
                  <Fingerprint size={14} className="text-[hsl(var(--primary))]" />
                  <span className="mono text-[10px] text-[hsl(var(--muted-foreground))]">PCA Vector: [{ztAssessment.deviceFingerprint.pcaVector.join(', ')}]</span>
                </div>
                <span className="mono text-[10px] text-[hsl(var(--primary))] truncate max-w-[140px]" title={ztAssessment.deviceFingerprint.fingerprintHash}>
                  HD: {ztAssessment.deviceFingerprint.fingerprintHash.slice(0, 10)}…
                </span>
              </div>
            </div>

            {/* Context Deviations & ABAC Rules Checked */}
            <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4">
              <div className="mono text-xs font-bold text-[hsl(var(--muted-foreground))] mb-3">
                Contextual Parameters & ABAC Validation Engine
              </div>

              <div className="grid grid-cols-3 gap-2 mb-4">
                <div className="rounded-lg border border-[hsl(var(--border))] p-2">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Spatial Dev (θ_l)</div>
                  <div className="mono mt-1 font-bold">{ztAssessment.contextBreakdown.spatialDeviation}%</div>
                </div>
                <div className="rounded-lg border border-[hsl(var(--border))] p-2">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Temporal Dev (θ_t)</div>
                  <div className="mono mt-1 font-bold">{ztAssessment.contextBreakdown.temporalDeviation}%</div>
                </div>
                <div className="rounded-lg border border-[hsl(var(--border))] p-2">
                  <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Resource Sens (θ_r)</div>
                  <div className="mono mt-1 font-bold">{ztAssessment.contextBreakdown.resourceSensitivityScore}%</div>
                </div>
              </div>

              <div className="space-y-2">
                {ztAssessment.abacRulesChecked.map((r, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    {r.passed ? (
                      <CheckCircle2 size={15} className="text-emerald-500 shrink-0 mt-0.5" />
                    ) : (
                      <XCircle size={15} className="text-red-500 shrink-0 mt-0.5" />
                    )}
                    <span className={r.passed ? 'text-[hsl(var(--foreground))]' : 'text-red-400 font-semibold'}>
                      {r.rule}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* Directory Table */}
      <Panel className="overflow-hidden">
        <div className="border-b border-[hsl(var(--border))] p-5">
          <SectionHead
            eyebrow="Directory"
            title="People & permissions"
            detail="Role changes are written to the immutable blockchain audit chain."
            action={
              <label className="relative hidden sm:block">
                <Search size={14} className="absolute left-3 top-2.5 text-[hsl(var(--muted-foreground))]" />
                <input
                  data-testid="input-search-users"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search directory"
                  className="h-9 w-52 rounded-lg border border-[hsl(var(--input))] bg-[hsl(var(--background))] pl-9 pr-3 text-xs outline-none focus:border-[hsl(var(--primary))]"
                />
              </label>
            }
          />
        </div>
        {!visible.length ? (
          <div className="p-5">
            <QueryState empty />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left">
              <thead className="bg-[hsl(var(--muted)/.6)]">
                <tr className="mono text-[10px] uppercase tracking-[.12em] text-[hsl(var(--muted-foreground))]">
                  <th className="px-5 py-3 font-medium">Identity</th>
                  <th className="px-4 py-3 font-medium">Trust</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Last login</th>
                  <th className="px-4 py-3 font-medium">Role</th>
                  <th className="px-4 py-3 text-right font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {visible.map((user) => (
                  <tr key={user.id} data-testid={`row-user-${user.id}`} className="transition hover:bg-[hsl(var(--muted)/.35)]">
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-3">
                        <div className="grid size-8 place-items-center rounded-full bg-[hsl(var(--primary)/.13)] text-[10px] font-extrabold text-[hsl(var(--primary))]">
                          {(user.username || 'User').slice(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div className="text-xs font-bold">{user.username || 'User'}</div>
                          <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">{user.maskedEmail}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-2">
                        <span className="mono text-xs font-medium">{user.trustScore}</span>
                        <div className="h-1.5 w-16 rounded-full bg-[hsl(var(--muted))]">
                          <div
                            className={`h-full rounded-full ${user.trustScore >= 80 ? 'bg-[hsl(var(--primary))]' : 'bg-[hsl(var(--chart-3))]'}`}
                            style={{ width: `${user.trustScore}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <RiskBadge risk={user.riskLevel} />
                    </td>
                    <td className="mono px-4 py-4 text-[10px] text-[hsl(var(--muted-foreground))]">
                      {user.lastLogin
                        ? new Date(user.lastLogin).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : 'Never'}
                    </td>
                    <td className="px-4 py-4">
                      <SelectField
                        label=""
                        value={user.role}
                        onChange={(e) => roleChange(user.id, e.target.value)}
                        className="w-[120px]"
                      >
                        <option value="Admin">Admin</option>
                        <option value="Analyst">Analyst</option>
                        <option value="User">User</option>
                      </SelectField>
                    </td>
                    <td className="px-4 py-4 text-right">
                      <Badge tone={user.status === 'Active' ? 'good' : 'warn'}>{user.status}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function MiniStat({ icon: Icon, label, value, color }: { icon: typeof Shield; label: string; value: number; color: string }) {
  return (
    <Panel className="flex items-center gap-3 p-4">
      <span className={`grid size-9 place-items-center rounded-lg bg-[hsl(var(--muted))] ${color}`}>
        <Icon size={17} />
      </span>
      <span>
        <span className="block text-xs font-semibold text-[hsl(var(--muted-foreground))]">{label}</span>
        <span className="mono mt-1 block text-xl">{value}</span>
      </span>
    </Panel>
  );
}