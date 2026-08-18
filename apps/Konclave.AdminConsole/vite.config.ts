import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
// https://vitest.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/setupTests.ts',
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        // Browser bootstrap: mounts the React root and has no unit-testable branch.
        'src/main.tsx',
        'src/setupTests.ts',
        'src/**/*.d.ts',
        // Telemetry bootstrap (present with IncludeOpenTelemetry): registers a global
        // WebTracerProvider on import instead of expressing application behavior.
        'src/telemetry.ts',
      ],
      thresholds: {
        lines: 85,
        statements: 85,
        functions: 85,
        branches: 80,
        perFile: true,
      },
    },
  },
});
