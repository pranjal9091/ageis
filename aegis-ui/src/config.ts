// Dynamic cloud & local runtime configuration
const isLocal = (): boolean => {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    return host === 'localhost' || host === '127.0.0.1' || window.location.port === '5173';
  }
  return true;
};

const getBaseUrl = (defaultPort: number): string => {
  if (typeof window !== 'undefined') {
    if (isLocal()) {
      const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
      return `${protocol}//${window.location.hostname || 'localhost'}:${defaultPort}`;
    }
    // In production (Render, Vercel, cloud), use same-origin without internal ports
    return window.location.origin;
  }
  return `http://localhost:${defaultPort}`;
};

const getWsUrl = (): string => {
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (isLocal()) {
      return `${protocol}//${window.location.hostname || 'localhost'}:8080/ws/telemetry`;
    }
    // In production, connect to same host with wss://
    return `${protocol}//${window.location.host}/ws/telemetry`;
  }
  return 'ws://localhost:8080/ws/telemetry';
};

export const PROXY_BASE_URL: string =
  import.meta.env.VITE_PROXY_URL || getBaseUrl(8080);

export const INTEL_BASE_URL: string =
  import.meta.env.VITE_INTEL_URL || getBaseUrl(5050);

export const WS_BASE_URL: string =
  import.meta.env.VITE_WS_URL || getWsUrl();
