import { useState } from 'react';
import { Link, useLocation } from 'wouter';
import { Activity, BarChart3, ChevronRight, FileClock, Fingerprint, Flame, LogOut, Menu, ShieldCheck, UsersRound, X } from 'lucide-react';
import { useLogout } from '@workspace/api-client-react';
import { Button } from '@/components/ui-kit';

import { useRealtimeSecurityStream } from '@/hooks/use-realtime-stream';

const navItems = [
  { href: '/', label: 'Overview', note: 'Daily posture', icon: BarChart3 },
  { href: '/access-control', label: 'Access control', note: 'Trust & roles', icon: UsersRound },
  { href: '/privacy', label: 'Privacy posture', note: 'Noise & masking', icon: Fingerprint },
  { href: '/intrusion-detection', label: 'Intrusion detection', note: 'Traffic signals', icon: Activity },
  { href: '/attack-simulator', label: 'Attack simulator', note: 'Red team & IPS', icon: Flame },
  { href: '/audit-logs', label: 'Audit integrity', note: 'Hash chain', icon: FileClock },
];

export function AppShell({ children, user }: { children: React.ReactNode; user: { username: string; role: string; trustScore: number; knownDevice: boolean } }) {
  const [open, setOpen] = useState(false);
  const [location, setLocation] = useLocation();
  const logout = useLogout();
  const { isConnected } = useRealtimeSecurityStream();
  const activePath = location;
  const signOut = () => logout.mutate(undefined, { onSuccess: () => setLocation('/login') });
  return <div className="noise min-h-[100dvh] bg-[hsl(var(--background))] text-[hsl(var(--foreground))]">
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-[260px] flex-col border-r border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar))] px-4 py-5 text-[hsl(var(--sidebar-foreground))] transition-transform duration-300 md:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}>
      <div className="mb-8 flex items-center justify-between px-2"><Link href="/" data-testid="link-brand" className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-xl bg-[hsl(var(--sidebar-primary))] text-[hsl(var(--sidebar-primary-foreground))]"><ShieldCheck size={19} strokeWidth={2.5} /></span><span><span className="block text-sm font-extrabold tracking-[-.03em]">Sentinel</span><span className="mono block text-[9px] uppercase tracking-[.15em] text-[hsl(var(--sidebar-foreground)/.52)]">security command</span></span></Link><button data-testid="button-close-menu" className="rounded-lg p-1 md:hidden" onClick={() => setOpen(false)}><X size={18} /></button></div>
      <div className="mono mb-2 px-2 text-[9px] font-medium uppercase tracking-[.2em] text-[hsl(var(--sidebar-foreground)/.42)]">Workspace</div>
      <nav className="space-y-1">{navItems.map(({ href, label, note, icon: Icon }) => { const active = activePath === href; return <Link key={href} href={href} onClick={() => setOpen(false)} data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`} className={`group flex items-center gap-3 rounded-lg px-2.5 py-2.5 transition ${active ? 'bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]' : 'text-[hsl(var(--sidebar-foreground)/.65)] hover:bg-[hsl(var(--sidebar-accent)/.7)] hover:text-[hsl(var(--sidebar-foreground))]'}`}><Icon size={17} className={active ? 'text-[hsl(var(--sidebar-primary))]' : ''} /><span className="min-w-0 flex-1"><span className="block text-xs font-bold">{label}</span><span className="block truncate text-[10px] text-[hsl(var(--sidebar-foreground)/.42)]">{note}</span></span>{active && <ChevronRight size={14} className="text-[hsl(var(--sidebar-primary))]" />}</Link> })}</nav>
      <div className="mt-auto space-y-4"><div className="rounded-xl border border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-accent)/.72)] p-3"><div className="mb-2 flex items-center justify-between"><span className="mono text-[9px] uppercase tracking-[.14em] text-[hsl(var(--sidebar-foreground)/.52)]">Session trust</span><span className="text-xs font-bold text-[hsl(var(--sidebar-primary))]">{user.trustScore}</span></div><div className="h-1.5 overflow-hidden rounded-full bg-[hsl(var(--sidebar)/.7)]"><div className="h-full rounded-full bg-[hsl(var(--sidebar-primary))]" style={{ width: `${Math.min(user.trustScore, 100)}%` }} /></div><p className="mt-2 text-[10px] text-[hsl(var(--sidebar-foreground)/.5)]">{user.knownDevice ? 'Known device' : 'New device detected'} · {user.role}</p></div><div className="flex items-center gap-2 px-2"><div className="grid size-8 place-items-center rounded-full bg-[hsl(var(--sidebar-primary)/.16)] text-xs font-extrabold text-[hsl(var(--sidebar-primary))]">{(user?.username || 'User').slice(0, 2).toUpperCase()}</div><div className="min-w-0 flex-1"><div className="truncate text-xs font-bold">{user?.username || 'User'}</div><div className="mono text-[9px] text-[hsl(var(--sidebar-foreground)/.46)]">current session</div></div><button data-testid="button-logout" onClick={signOut} title="Sign out" className="rounded-lg p-2 text-[hsl(var(--sidebar-foreground)/.55)] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-foreground))]"><LogOut size={15} /></button></div></div>
    </aside>
    {open && <button data-testid="button-overlay-menu" className="fixed inset-0 z-30 bg-[hsl(216_30%_12%/.32)] md:hidden" onClick={() => setOpen(false)} aria-label="Close menu" />}
    <div className="md:pl-[260px]"><header className="sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-[hsl(var(--border))] bg-[hsl(var(--background)/.9)] px-5 backdrop-blur md:px-8"><button data-testid="button-open-menu" className="rounded-lg p-2 hover:bg-[hsl(var(--muted))] md:hidden" onClick={() => setOpen(true)}><Menu size={20} /></button><div className="hidden items-center gap-2 text-xs text-[hsl(var(--muted-foreground))] md:flex"><span className={`size-2 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />{isConnected ? 'Real-time stream connected' : 'System monitoring active'}</div><div className="flex items-center gap-2"><span className="mono hidden text-[10px] uppercase tracking-[.13em] text-[hsl(var(--muted-foreground))] sm:block">Local time</span><span className="mono text-xs font-medium">{new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div></header><main className="mx-auto max-w-[1500px] px-5 py-7 md:px-8 md:py-9">{children}</main></div>
  </div>;
}