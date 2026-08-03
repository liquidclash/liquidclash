import {
  cloudflareTest,
  readD1Migrations,
} from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const testSecrets = {
  JWT_SECRET: 'test-jwt-secret-with-at-least-32-characters',
  ADMIN_API_TOKEN: 'admin-test-token-with-at-least-32-characters',
  HOME_AGENT_TOKEN: 'home-test-token-with-at-least-32-characters',
  TAILSCALE_OAUTH_CLIENT_ID: 'test',
  TAILSCALE_OAUTH_CLIENT_SECRET: 'tailscale-test-secret-with-at-least-32-characters',
  RESEND_API_KEY: 're_test-key-with-at-least-32-characters',
  CATALOG_ENCRYPTION_KEY: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY',
};
Object.assign(process.env, testSecrets);

const migrations = await readD1Migrations('./migrations');

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          ...testSecrets,
          EMAIL_FROM: 'login@example.com',
          APPLE_CLIENT_ID: 'com.raydocs.tono',
          GOOGLE_CLIENT_ID: 'test-google-client.apps.googleusercontent.com',
          DIRECT_SIGNUP_ALLOWLIST: '@example.com',
          TAILSCALE_ENROLLMENT_ENABLED: 'true',
          TEST_MIGRATIONS: migrations,
          // Low thresholds so rate-limit tests finish quickly
          RATE_LIMIT_WINDOW_SECONDS: '900',
          RATE_LIMIT_EMAIL_START_IP: '50',
          RATE_LIMIT_EMAIL_START_EMAIL: '20',
          RATE_LIMIT_EMAIL_VERIFY_IP: '30',
          RATE_LIMIT_EMAIL_VERIFY_CHALLENGE: '3',
          RATE_LIMIT_OIDC_START_IP: '30',
          RATE_LIMIT_OIDC_START_INSTALLATION: '10',
          RATE_LIMIT_OIDC_VERIFY_IP: '30',
          RATE_LIMIT_OIDC_VERIFY_CHALLENGE: '3',
        },
        d1Databases: { DB: 'test-db' },
      },
    }),
  ],
  test: {
    maxWorkers: 1,
    setupFiles: ['./test/setup.ts'],
  },
});
