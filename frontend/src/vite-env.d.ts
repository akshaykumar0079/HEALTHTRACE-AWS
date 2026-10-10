/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin for split deployments, e.g. https://healthtrace-api.onrender.com. Empty = same origin. */
  readonly VITE_API_BASE_URL?: string;
  /** Full WebSocket URL, e.g. wss://healthtrace-api.onrender.com/ws. Derived from VITE_API_BASE_URL if unset. */
  readonly VITE_WS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
