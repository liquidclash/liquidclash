import { applyD1Migrations, env, type D1Migration } from 'cloudflare:test';
import { beforeAll, beforeEach } from 'vitest';

declare global {
  namespace Cloudflare {
    interface Env {
      DB: D1Database;
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});

// The Vitest 4 Workers pool isolates storage per test file (rather than per
// individual test). Reset mutable rows explicitly so tests cannot pass or fail
// based on execution order.
beforeEach(async () => {
  await env.DB.prepare('DROP TRIGGER IF EXISTS test_fail_activation').run();
  await env.DB.prepare('DELETE FROM device_actions').run();
  await env.DB.prepare('DELETE FROM diagnostics_reports').run();
  await env.DB.prepare('DELETE FROM sessions').run();
  await env.DB.prepare('DELETE FROM usage_reports').run();
  await env.DB.prepare('DELETE FROM revocation_jobs').run();
  await env.DB.prepare('DELETE FROM devices').run();
  await env.DB.prepare('DELETE FROM auth_challenges').run();
  await env.DB.prepare('DELETE FROM auth_identities').run();
  await env.DB.prepare('DELETE FROM invitations').run();
  await env.DB.prepare('DELETE FROM managed_exit_catalog').run();
  await env.DB.prepare('DELETE FROM managed_traffic_policy').run();
  await env.DB.prepare('DELETE FROM users').run();
  await env.DB.prepare('DELETE FROM rate_limits').run();
});
