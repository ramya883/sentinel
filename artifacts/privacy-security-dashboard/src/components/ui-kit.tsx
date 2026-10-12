import { type ReactNode } from 'react';
import { AlertCircle, CheckCircle2, ChevronDown, LoaderCircle } from 'lucide-react';

export function Button({ children, className = '', variant = 'primary', loading = false, ...props }: { children: ReactNode; className?: string; variant?: 'primary' | 'quiet' | 'outline' | 'danger'; loading?: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const styles = {
    primary: 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:brightness-95',
    quiet: 'bg-[hsl(var(--muted))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--secondary))]',
    outline: 'border border-[hsl(var(--border))] bg-transparent text-[hsl(var(--foreground))] hover:bg-[hsl(var(--muted))]',
    danger: 'bg-[hsl(var(--destructive))] text-[hsl(var(--destructive-foreground))] hover:brightness-95',
  };
  return <button {...props} disabled={loading || props.disabled} className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition duration-200 disabled:cursor-not-allowed disabled:opacity-55 ${styles[variant]} ${className}`}>{loading && <LoaderCircle size={15} className="animate-spin" />}{children}</button>;
}

export function Panel({ children, className = '', ...props }: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>) {
  return <section {...props} className={`rounded-xl border border-[hsl(var(--card-border))] bg-[hsl(var(--card))] shadow-[0_8px_24px_hsl(215_30%_17%_/_0.035)] ${className}`}>{children}</section>;
}

export function SectionHead({ eyebrow, title, detail, action }: { eyebrow?: string; title: string; detail?: string; action?: ReactNode }) {
  return <div className="mb-4 flex items-start justify-between gap-4"><div><div className="mono mb-1 text-[10px] font-medium uppercase tracking-[.18em] text-[hsl(var(--muted-foreground))]">{eyebrow}</div><h2 className="text-[17px] font-extrabold tracking-[-.03em]">{title}</h2>{detail && <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">{detail}</p>}</div>{action}</div>;
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'good' | 'warn' | 'danger' | 'info' }) {
  const styles = { neutral: 'bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]', good: 'bg-[hsl(156_39%_40%_/_0.12)] text-[hsl(156_39%_32%)]', warn: 'bg-[hsl(39_76%_55%_/_0.16)] text-[hsl(34_75%_32%)]', danger: 'bg-[hsl(4_64%_54%_/_0.13)] text-[hsl(4_64%_45%)]', info: 'bg-[hsl(215_44%_52%_/_0.13)] text-[hsl(215_44%_42%)]' }; 
  return <span className={`inline-flex items-center rounded-full px-2 py-1 text-[10px] font-bold uppercase tracking-[.08em] ${styles[tone]}`}>{children}</span>;
}

export function RiskBadge({ risk }: { risk: string }) {
  return <Badge tone={risk === 'High' ? 'danger' : risk === 'Medium' ? 'warn' : 'good'}>{risk}</Badge>;
}

export function QueryState({ loading, error, empty, retry }: { loading?: boolean; error?: boolean; empty?: boolean; retry?: () => void }) {
  if (loading) return <div className="space-y-3 py-3" data-testid="state-loading"><div className="h-4 w-1/3 animate-pulse rounded bg-[hsl(var(--muted))]" /><div className="h-10 w-full animate-pulse rounded bg-[hsl(var(--muted))]" /><div className="h-10 w-4/5 animate-pulse rounded bg-[hsl(var(--muted))]" /></div>;
  if (error) return <div className="flex items-center gap-3 rounded-lg border border-[hsl(var(--destructive)/.22)] bg-[hsl(var(--destructive)/.06)] p-4 text-sm" data-testid="state-error"><AlertCircle size={17} className="text-[hsl(var(--destructive))]" /><span>Unable to load this signal.</span>{retry && <button data-testid="button-retry" onClick={retry} className="ml-auto font-semibold underline">Retry</button>}</div>;
  if (empty) return <div className="flex items-center gap-3 rounded-lg border border-dashed border-[hsl(var(--border))] p-7 text-sm text-[hsl(var(--muted-foreground))]" data-testid="state-empty"><CheckCircle2 size={17} className="text-[hsl(var(--primary))]" />No records in this view.</div>;
  return null;
}

export function Field({ label, hint, ...props }: { label: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return <label className="block space-y-1.5"><span className="flex items-center justify-between text-xs font-bold text-[hsl(var(--foreground))]"><span>{label}</span>{hint && <span className="mono text-[10px] font-normal text-[hsl(var(--muted-foreground))]">{hint}</span>}</span><input {...props} className={`h-10 w-full rounded-lg border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 text-sm outline-none transition placeholder:text-[hsl(var(--muted-foreground))] focus:border-[hsl(var(--primary))] focus:ring-2 focus:ring-[hsl(var(--ring)/.14)] ${props.className ?? ''}`} /></label>;
}

export function SelectField({ label, value, onChange, children, className = '' }: { label: string; value: string; onChange: (event: React.ChangeEvent<HTMLSelectElement>) => void; children: ReactNode; className?: string }) {
  return <label className={`block space-y-1.5 ${className}`}><span className="text-xs font-bold">{label}</span><span className="relative block"><select value={value} onChange={onChange} className="h-10 w-full appearance-none rounded-lg border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 pr-8 text-sm outline-none focus:border-[hsl(var(--primary))]">{children}</select><ChevronDown size={15} className="pointer-events-none absolute right-3 top-3 text-[hsl(var(--muted-foreground))]" /></span></label>;
}