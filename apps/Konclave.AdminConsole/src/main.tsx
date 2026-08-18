// Telemetry must initialize before any other module emits a fetch or user event,
// so it sits at the very top of the import order. The side-effect import boots
// the WebTracerProvider; ./telemetry also re-exports a `tracer` for callers
// that want to emit custom spans.
import './telemetry';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './App.css';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
