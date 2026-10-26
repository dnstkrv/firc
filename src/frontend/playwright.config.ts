import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.PW_PORT ?? 5173);

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "list",
  outputDir: "node_modules/.playwright-results",
  use: {
    baseURL: `http://localhost:${port}`,
    trace: "off",
    screenshot: process.env.CI ? "only-on-failure" : "off",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: port === 5173 ? "npm run dev:frontend" : `npx vite --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: !process.env.CI,
  },
});
