import { defineConfig, devices } from '@playwright/test';

const PORT = 4626;
const BASE = '/crypto-lab-downgrade-wire/';

export default defineConfig({
  testDir: './e2e',
  // The a11y gate drives ~24 states per configuration and runs a full axe pass
  // plus an arithmetic contrast walk after every one, with a real ML-KEM-768
  // encapsulation behind several of the clicks. The 30s default is not close;
  // the a11y spec raises its own ceiling further with `test.setTimeout`.
  timeout: 120_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
