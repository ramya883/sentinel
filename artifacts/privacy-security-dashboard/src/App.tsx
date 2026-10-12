import { type ReactNode, useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { AppShell } from '@/components/app-shell';
import { LoginPage, RegisterPage } from '@/pages/auth';
import { DashboardPage } from '@/pages/dashboard';
import { AccessControlPage } from '@/pages/access-control';
import { PrivacyPage } from '@/pages/privacy';
import { IntrusionDetectionPage } from '@/pages/intrusion-detection';
import { AttackSimulatorPage } from '@/pages/attack-simulator';
import { AuditLogsPage } from '@/pages/audit-logs';
import { useGetCurrentUser, getGetCurrentUserQueryKey } from '@workspace/api-client-react';
import {
  Route,
  Switch,
  useLocation,
  Router as WouterRouter,
} from 'wouter';

const queryClient = new QueryClient();

function Router() {
  const [location, setLocation] = useLocation();
  if (location === '/login') return <LoginPage />;
  if (location === '/register') return <RegisterPage />;
  return (
    // Keep a shared shell (sidebar, navbar) outside the boundary so it
    // survives a page crash.
    <RoutedErrorBoundary>
      <ProtectedGate setLocation={setLocation} />
    </RoutedErrorBoundary>
  );
}

function ProtectedGate({ setLocation }: { setLocation: (path: string) => void }) {
  const currentUser = useGetCurrentUser({ query: { retry: false, queryKey: getGetCurrentUserQueryKey() } });
  useEffect(() => {
    if (currentUser.isError) setLocation('/login');
  }, [currentUser.isError, setLocation]);
  if (currentUser.isLoading || currentUser.isError || !currentUser.data) return <div className="grid min-h-[100dvh] place-items-center bg-[hsl(var(--background))]"><div className="w-64 space-y-3"><div className="h-2 animate-pulse rounded bg-[hsl(var(--muted))]" /><div className="h-8 animate-pulse rounded bg-[hsl(var(--muted))]" /><div className="mono text-center text-[10px] uppercase tracking-[.18em] text-[hsl(var(--muted-foreground))]">Establishing secure session</div></div></div>;
  return <AppShell user={currentUser.data}><Switch><Route path="/" component={DashboardPage} /><Route path="/access-control" component={AccessControlPage} /><Route path="/privacy" component={PrivacyPage} /><Route path="/intrusion-detection" component={IntrusionDetectionPage} /><Route path="/attack-simulator" component={AttackSimulatorPage} /><Route path="/audit-logs" component={AuditLogsPage} /><Route component={NotFound} /></Switch></AppShell>;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
