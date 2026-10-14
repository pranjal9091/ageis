// Dynamic cloud & local runtime configuration
const getHost = (): string => {
  if (typeof window !== 'undefined') {
    return window.location.hostname || 'localhost';
  }
  return 'localhost';
};

const getProtocol = (secure: boolean): string => {
  if (typeof window !== 'undefined') {
    return window.location.protocol === 'https:'
      ? secure ? 'wss:' : 'https:'
      : secure ? 'ws:' : 'http:';
  }
  return secure ? 'ws:' : 'http:';
};

export const PROXY_BASE_URL: string =
  import.meta.env.VITE_PROXY_URL || `${getProtocol(false)}//${getHost()}:8080`;

export const INTEL_BASE_URL: string =
  import.meta.env.VITE_INTEL_URL || `${getProtocol(false)}//${getHost()}:5050`;

export const WS_BASE_URL: string =
  import.meta.env.VITE_WS_URL || `${getProtocol(true)}//${getHost()}:8080/ws/telemetry`;
