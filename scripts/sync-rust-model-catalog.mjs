import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { PROVIDER_MODELS } from "../open-sse/config/providerModels.js";
import { PROVIDERS } from "../open-sse/config/providers.js";
import REGISTRY from "../open-sse/providers/registry/index.js";
import { getCapabilitiesForModel } from "../open-sse/providers/capabilities.js";
import { CLI_TOOLS } from "../src/shared/constants/cliTools.js";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const aliasesToIds = new Map();
const registryModels = new Map();
for (const entry of REGISTRY) {
  aliasesToIds.set(entry.id, entry.id);
  if (entry.alias) aliasesToIds.set(entry.alias, entry.id);
  for (const alias of entry.aliases || []) aliasesToIds.set(alias, entry.id);
  for (const model of entry.models || []) {
    registryModels.set(`${entry.id}/${model.id}`, model.contextLength || null);
  }
}
const catalog = Object.entries(PROVIDER_MODELS).flatMap(([provider, models]) => models.map(({ id: model, name, kind, type, contextLength }) => {
  const providerAlias = provider;
  const providerId = aliasesToIds.get(providerAlias) || providerAlias;
  const capabilities = getCapabilitiesForModel(providerId, model);
  const fullModel = `${provider}/${model}`;
  const routedModel = `${providerAlias}/${model}`;
  return {
    provider,
    providerAlias,
    providerId,
    model,
    kind: kind || type || "llm",
    name: name || model,
    contextLength: contextLength || registryModels.get(`${providerId}/${model}`) || null,
    fullModel,
    routedModel,
    caps: {
      vision: capabilities.vision,
      search: capabilities.search,
      reasoning: capabilities.reasoning,
      contextWindow: capabilities.contextWindow,
      maxOutput: capabilities.maxOutput,
    },
  };
}));

await writeFile(
  join(projectRoot, "rust/src/model_catalog.json"),
  `${JSON.stringify(catalog, null, 2)}\n`,
);
const textHeaders = (headers) => Object.fromEntries(
  Object.entries(headers || {}).filter(([, value]) => typeof value === "string"),
);
const providerMetadata = Object.fromEntries(REGISTRY.map((entry) => {
  const config = PROVIDERS[entry.id] || {};
  const mediaConfig = entry.ttsConfig || entry.sttConfig || entry.embeddingConfig
    || entry.imageConfig || entry.videoConfig || entry.musicConfig;
  const webConfig = entry.searchConfig || entry.fetchConfig;
  return [entry.id, {
    name: entry.display?.name || entry.id,
    category: entry.category,
    authType: entry.authType || (entry.category === "oauth" ? "oauth" : "apikey"),
    noAuth: entry.noAuth === true || config.noAuth === true,
    credentialForm: entry.credentialForm || null,
    apiKeyOptionalWith: entry.apiKeyOptionalWith || null,
    serviceKinds: entry.serviceKinds || ["llm"],
    probe: {
      baseUrl: config.baseUrl || "",
      validateUrl: config.validateUrl || "",
      format: config.format || "",
      authHeader: config.auth?.apiKey?.header || config.authHeader || "bearer",
      authScheme: config.auth?.apiKey?.scheme || "bearer",
      noAuth: config.noAuth === true,
      headers: textHeaders(config.headers),
    },
    ...(webConfig ? { webProbe: {
      baseUrl: webConfig.validateUrl || webConfig.baseUrl || "",
      method: webConfig.method || "GET",
      authHeader: webConfig.authHeader || "bearer",
      authType: webConfig.authType || "apikey",
      extraHeaders: textHeaders(webConfig.extraHeaders),
    } } : {}),
    ...(mediaConfig ? { mediaProbe: {
      baseUrl: mediaConfig.baseUrl || "",
      method: mediaConfig.method || "POST",
      authHeader: mediaConfig.authHeader || "bearer",
      authType: mediaConfig.authType || "apikey",
      extraHeaders: textHeaders(mediaConfig.extraHeaders),
    } } : {}),
  }];
}));
await writeFile(
  join(projectRoot, "rust/src/provider_metadata.json"),
  `${JSON.stringify(providerMetadata, null, 2)}\n`,
);
const validComboName = (name) => /^[a-zA-Z0-9_.-]+$/.test(name || "");
const cursorPresets = (PROVIDER_MODELS.cu || []).filter((entry) => validComboName(entry.id))
  .map((entry) => ({ name: entry.id, models: [`cu/${entry.id}`] }));
const claudePresets = [];
const seenClaude = new Set();
for (const entry of PROVIDER_MODELS.cc || []) {
  if (!validComboName(entry.id) || seenClaude.has(entry.id)) continue;
  seenClaude.add(entry.id);
  claudePresets.push({ name: entry.id, models: [`cc/${entry.id}`] });
}
const claudeTool = CLI_TOOLS.claude || {};
for (const entry of claudeTool.defaultModels || []) {
  const name = entry.alias || entry.id;
  if (!validComboName(name) || !entry.defaultValue || seenClaude.has(name)) continue;
  seenClaude.add(name);
  claudePresets.push({ name, models: [entry.defaultValue] });
}
for (const [name, model] of Object.entries({ default: "cc/claude-sonnet-5", opusplan: "cc/claude-opus-5" })) {
  if (seenClaude.has(name)) continue;
  seenClaude.add(name);
  claudePresets.push({ name, models: [model] });
}
await writeFile(
  join(projectRoot, "rust/src/combo_presets.json"),
  `${JSON.stringify({ cursor: cursorPresets, claude: claudePresets }, null, 2)}\n`,
);
process.stdout.write(`Wrote ${catalog.length} Rust model catalog entries.\n`);
