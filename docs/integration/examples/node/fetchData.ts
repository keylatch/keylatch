#!/usr/bin/env npx tsx
/**
 * fetchData.ts — Keylatch Node.js/TypeScript integration reference example.
 *
 * Run with:
 *   keylatch run --clean-env --runtime gateway_typed openrouter -- npx tsx fetchData.ts
 *
 * This script demonstrates reading KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN
 * from process.env (injected by keylatch run) and fetching a model list.
 *
 * No raw credentials appear in this script. The gateway token is short-lived
 * and scoped to this keylatch session.
 *
 * Requirements:
 *   Node 18+ (fetch built-in) or install node-fetch
 */

/** Gateway credentials injected by `keylatch run`. */
interface GatewayEnv {
  gatewayUrl: string;
  gatewayToken: string;
}

/** A single model entry from the /v1/models response. */
interface ModelEntry {
  id: string;
  object?: string;
  created?: number;
  owned_by?: string;
}

/** The /v1/models response envelope. */
interface ModelsResponse {
  data: ModelEntry[];
  object?: string;
}

/**
 * Read and validate Keylatch gateway env vars.
 * Exits with a helpful error message if they are missing.
 */
function requireGatewayEnv(): GatewayEnv {
  const gatewayUrl   = process.env.KEYLATCH_GATEWAY_URL   ?? '';
  const gatewayToken = process.env.KEYLATCH_GATEWAY_TOKEN ?? '';

  if (!gatewayUrl || !gatewayToken) {
    console.error(
      'ERROR: KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are not set.\n' +
      '\n' +
      'This script must be run inside keylatch run:\n' +
      '\n' +
      '  keylatch run --clean-env openrouter -- npx tsx fetchData.ts\n' +
      '\n' +
      'If you have not connected a provider yet:\n' +
      '  keylatch setup\n' +
      '  keylatch connect openrouter',
    );
    process.exit(1);
  }

  return { gatewayUrl, gatewayToken };
}

/**
 * Fetch the model list from the Keylatch gateway.
 */
async function fetchModels(
  gatewayUrl: string,
  gatewayToken: string,
): Promise<ModelEntry[]> {
  let resp: Response;

  try {
    resp = await fetch(`${gatewayUrl}/v1/models`, {
      headers: {
        Authorization: `Bearer ${gatewayToken}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Cannot reach gateway at ${gatewayUrl}: ${message}\n` +
      'Is the gateway running? Try: keylatch gateway up --detach',
    );
  }

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} from gateway: ${body}`);
  }

  const data: ModelsResponse = await resp.json() as ModelsResponse;
  return data.data ?? [];
}

async function main(): Promise<void> {
  const { gatewayUrl, gatewayToken } = requireGatewayEnv();

  console.log(`Fetching models from ${gatewayUrl} ...`);

  const models = await fetchModels(gatewayUrl, gatewayToken);

  if (models.length === 0) {
    console.log('No models returned — check your provider configuration.');
    return;
  }

  console.log(`\nAvailable models (${models.length} total):\n`);
  for (const m of models.slice(0, 10)) {
    console.log(`  ${m.id}`);
  }
  if (models.length > 10) {
    console.log(`  ... and ${models.length - 10} more`);
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`Fatal: ${message}`);
  process.exit(1);
});
