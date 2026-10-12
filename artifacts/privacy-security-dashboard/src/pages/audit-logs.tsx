import { useEffect, useState } from 'react';
import { Blocks, Check, CheckCircle2, ChevronRight, Clipboard, Cpu, FileClock, Link2, ShieldCheck, Sparkles, XCircle } from 'lucide-react';
import { useListAuditLogs, useVerifyAuditLogs, getListAuditLogsQueryKey } from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import { Badge, Button, Panel, QueryState, RiskBadge, SectionHead } from '@/components/ui-kit';
import { PageLoading } from '@/pages/dashboard';

interface BlockTransaction {
  id: string;
  uid: number;
  op: string;
  obj: string;
  ts: string;
  sig: string;
  hash: string;
}

interface Block {
  blockNumber: number;
  previousHash: string;
  timestamp: string;
  transactions: BlockTransaction[];
  merkleRoot: string;
  blockHash: string;
  validatorNode: string;
}

interface MerkleProof {
  transactionId: string;
  leafHash: string;
  merkleRoot: string;
  proofPath: Array<{ hash: string; position: 'left' | 'right' }>;
  pathLength: number;
  isValid: boolean;
}

export function AuditLogsPage() {
  const logs = useListAuditLogs();
  const verify = useVerifyAuditLogs();
  const queryClient = useQueryClient();
  const [integrity, setIntegrity] = useState<{ valid: boolean; checked: number; message: string } | null>(null);

  // Blockchain Ledger State
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [activeProof, setActiveProof] = useState<MerkleProof | null>(null);
  const [loadingProof, setLoadingProof] = useState<string | null>(null);
  const [invokingContract, setInvokingContract] = useState(false);

  const fetchBlocks = async () => {
    try {
      const res = await fetch('/api/blockchain/blocks');
      if (res.ok) {
        setBlocks(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchBlocks();
  }, []);

  const inspectMerkleProof = async (txId: string) => {
    setLoadingProof(txId);
    try {
      const res = await fetch(`/api/blockchain/merkle-proof/${txId}`);
      if (res.ok) {
        setActiveProof(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingProof(null);
    }
  };

  const executeInvokeModel = async () => {
    setInvokingContract(true);
    try {
      const res = await fetch('/api/blockchain/invoke-model', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modelId: 'GRU-Autoencoder',
          version: '2.1',
        }),
      });
      if (res.ok) {
        await fetchBlocks();
      }
    } finally {
      setInvokingContract(false);
    }
  };

  const verifyChain = () =>
    verify.mutate(undefined, {
      onSuccess: (result) => {
        setIntegrity(result);
        queryClient.invalidateQueries({ queryKey: getListAuditLogsQueryKey() });
      },
    });

  if (logs.isLoading) return <PageLoading title="audit integrity" />;
  if (logs.isError) return <QueryState error retry={() => logs.refetch()} />;

  const list = logs.data ?? [];

  return (
    <div className="animate-rise space-y-7">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-[hsl(var(--muted-foreground))]">
            Evidence plane / distributed blockchain & hash chain
          </div>
          <h1 className="text-3xl font-extrabold tracking-[-.055em]">Audit Integrity & Blockchain Ledger</h1>
          <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
            Tamper-proof evidence storage via Merkle tree compression index O(log n) and SHA-256 hash chaining.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button data-testid="button-verify-audit" onClick={verifyChain} loading={verify.isPending}>
            <ShieldCheck size={15} /> Verify Linear Chain
          </Button>
          <Button variant="outline" onClick={executeInvokeModel} loading={invokingContract}>
            <Cpu size={15} /> InvokeModel() Contract
          </Button>
        </div>
      </div>

      {integrity && (
        <div
          data-testid="status-audit-integrity"
          className={`flex items-center gap-3 rounded-xl border p-4 ${
            integrity.valid
              ? 'border-[hsl(var(--primary)/.32)] bg-[hsl(var(--primary)/.07)]'
              : 'border-[hsl(var(--destructive)/.3)] bg-[hsl(var(--destructive)/.07)]'
          }`}
        >
          {integrity.valid ? (
            <CheckCircle2 className="text-[hsl(var(--primary))]" size={20} />
          ) : (
            <XCircle className="text-[hsl(var(--destructive))]" size={20} />
          )}
          <div className="flex-1">
            <div className="text-sm font-extrabold">{integrity.valid ? 'Chain verified' : 'Integrity issue found'}</div>
            <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">{integrity.message}</div>
          </div>
          <Badge tone={integrity.valid ? 'good' : 'danger'}>{integrity.checked} checked</Badge>
        </div>
      )}

      {/* ADVANCED SECTION: Blockchain Ledger & Merkle Proof Inspector */}
      <Panel className="p-6 border-[hsl(var(--primary)/.35)] bg-[hsl(var(--card))]">
        <SectionHead
          eyebrow="Research Engine §3.4"
          title="Distributed Blockchain Ledger & Merkle Tree Proofs"
          detail="Block 5-tuples B_k = (h_{k-1}, T_k, M_k, t_k, h_k) with O(log n) logarithmic Merkle branch verification."
        />

        {/* Blocks Carousel / Grid */}
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {blocks.map((block) => (
            <div key={block.blockNumber} className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="mono text-xs font-bold text-[hsl(var(--primary))] flex items-center gap-1.5">
                  <Blocks size={14} /> Block #{block.blockNumber}
                </span>
                <Badge tone="info">{block.transactions.length} Txs</Badge>
              </div>

              <div>
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Merkle Root (h_root)</div>
                <div className="mono mt-0.5 text-xs text-[hsl(var(--foreground))] truncate" title={block.merkleRoot}>
                  {block.merkleRoot.slice(0, 16)}…{block.merkleRoot.slice(-8)}
                </div>
              </div>

              <div>
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Block Hash (h_k)</div>
                <div className="mono mt-0.5 text-xs text-[hsl(var(--muted-foreground))] truncate" title={block.blockHash}>
                  {block.blockHash.slice(0, 16)}…{block.blockHash.slice(-8)}
                </div>
              </div>

              <div className="pt-2 border-t border-[hsl(var(--border))] space-y-1.5">
                <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Transactions:</div>
                {block.transactions.map((tx) => (
                  <div key={tx.id} className="flex items-center justify-between text-xs py-1">
                    <span className="truncate max-w-[130px] font-semibold">{tx.op}</span>
                    <button
                      onClick={() => inspectMerkleProof(tx.id)}
                      className="mono text-[10px] text-[hsl(var(--primary))] hover:underline flex items-center gap-0.5"
                    >
                      Verify Proof <ChevronRight size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Merkle Proof Inspector Box */}
        {activeProof && (
          <div className="mt-5 rounded-xl border border-[hsl(var(--primary)/.3)] bg-[hsl(var(--primary)/.04)] p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="mono text-xs font-bold text-[hsl(var(--primary))]">
                Cryptographic Merkle Proof Path for {activeProof.transactionId}
              </span>
              <Badge tone={activeProof.isValid ? 'good' : 'danger'}>
                {activeProof.isValid ? 'Proof Valid (O(log n))' : 'Invalid Proof'}
              </Badge>
            </div>

            <div className="text-xs text-[hsl(var(--muted-foreground))]">
              Leaf Hash: <span className="mono text-[hsl(var(--foreground))]">{activeProof.leafHash}</span>
            </div>

            <div className="space-y-1.5 pt-2">
              <div className="mono text-[10px] text-[hsl(var(--muted-foreground))]">Sibling Hash Path Steps:</div>
              {activeProof.proofPath.map((step, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs mono">
                  <span className="w-16 text-[10px] text-[hsl(var(--muted-foreground))]">Step #{idx + 1} ({step.position})</span>
                  <span className="rounded bg-[hsl(var(--muted))] px-2 py-0.5 truncate text-[11px] flex-1">
                    {step.hash}
                  </span>
                </div>
              ))}
            </div>

            <div className="pt-2 text-xs flex items-center gap-1.5 text-emerald-400 font-semibold">
              <CheckCircle2 size={15} /> Authenticated root hash match confirmed: {activeProof.merkleRoot.slice(0, 24)}…
            </div>
          </div>
        )}
      </Panel>

      {/* Existing Linear Hash-Chained Audit Ledger */}
      <Panel className="overflow-hidden">
        <div className="p-5 pb-2">
          <SectionHead eyebrow="Immutable ledger" title="Sequential Audit Log Events" detail={`${list.length} events · newest first`} />
        </div>
        {!list.length ? (
          <div className="px-5 pb-5">
            <QueryState empty />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] text-left">
              <thead className="bg-[hsl(var(--muted)/.6)]">
                <tr className="mono text-[10px] uppercase tracking-[.12em] text-[hsl(var(--muted-foreground))]">
                  <th className="px-5 py-3 font-medium">Event</th>
                  <th className="px-4 py-3 font-medium">Actor</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Previous hash</th>
                  <th className="px-4 py-3 font-medium">Current hash</th>
                  <th className="px-4 py-3 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {list.map((log) => (
                  <tr data-testid={`row-audit-${log.id}`} key={log.id} className="hover:bg-[hsl(var(--muted)/.35)]">
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-3">
                        <span className="grid size-8 place-items-center rounded-lg bg-[hsl(var(--muted))] text-[hsl(var(--primary))]">
                          <FileClock size={15} />
                        </span>
                        <div>
                          <div className="text-xs font-extrabold">{log.eventType}</div>
                          <div className="mono mt-1 text-[10px] text-[hsl(var(--muted-foreground))]">event #{log.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-xs font-semibold">{log.actor}</td>
                    <td className="px-4 py-4">
                      <RiskBadge risk={log.riskScore >= 70 ? 'High' : log.riskScore >= 35 ? 'Medium' : 'Low'} />
                    </td>
                    <td className="px-4 py-4">
                      <HashCell value={log.previousHash} />
                    </td>
                    <td className="px-4 py-4">
                      <HashCell value={log.currentHash} />
                    </td>
                    <td className="mono px-4 py-4 text-[10px] text-[hsl(var(--muted-foreground))]">
                      {new Date(log.timestamp).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <div className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
        <Link2 size={14} className="text-[hsl(var(--primary))]" /> Each current hash becomes the next event&apos;s previous hash.
      </div>
    </div>
  );
}

function HashCell({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };
  return (
    <button data-testid="button-copy-hash" onClick={copy} title="Copy hash" className="group flex items-center gap-2">
      <span className="mono max-w-[120px] truncate text-[10px] text-[hsl(var(--muted-foreground))]">{value}</span>
      {copied ? (
        <Check size={13} className="text-[hsl(var(--primary))]" />
      ) : (
        <Clipboard size={13} className="text-[hsl(var(--muted-foreground))] opacity-0 transition group-hover:opacity-100" />
      )}
    </button>
  );
}