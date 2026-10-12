import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  getGetDashboardQueryKey,
  getListAuditLogsQueryKey,
  getListIntrusionEventsQueryKey,
  getGetPrivacyQueryKey,
} from '@workspace/api-client-react';

export function useRealtimeSecurityStream() {
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const streamUrl = '/api/security/stream';
    const eventSource = new EventSource(streamUrl);

    eventSource.onopen = () => {
      setIsConnected(true);
    };

    eventSource.onerror = () => {
      setIsConnected(false);
    };

    eventSource.addEventListener('connected', () => {
      setIsConnected(true);
    });

    eventSource.addEventListener('audit_log', () => {
      queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListAuditLogsQueryKey() });
    });

    eventSource.addEventListener('intrusion_detected', () => {
      queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListIntrusionEventsQueryKey() });
    });

    eventSource.addEventListener('privacy_updated', () => {
      queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetPrivacyQueryKey() });
    });

    return () => {
      eventSource.close();
      setIsConnected(false);
    };
  }, [queryClient]);

  return { isConnected };
}
