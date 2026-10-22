import { spawnSync } from "node:child_process";
import { existsSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const apiRoutes = join(projectRoot, "src", "app", "api");
const temporarilyDisabledApiRoutes = join(projectRoot, ".next-static-api-routes");
const proxyEntry = join(projectRoot, "src", "proxy.js");
const temporarilyDisabledProxyEntry = join(projectRoot, "src", "proxy.js.static-disabled");
const bootstrapEntry = join(projectRoot, "src", "shared", "services", "bootstrap.js");
const temporarilyDisabledBootstrapEntry = `${bootstrapEntry}.static-disabled`;
const nextCli = join(projectRoot, "node_modules", "next", "dist", "bin", "next");
const syncModelCatalog = join(projectRoot, "scripts", "sync-rust-model-catalog.mjs");

const syncResult = spawnSync(process.execPath, [syncModelCatalog], {
  cwd: projectRoot,
  stdio: "inherit",
});
if (syncResult.error) throw syncResult.error;
if (syncResult.signal) throw new Error(`Model catalog generation was interrupted by ${syncResult.signal}`);
if (syncResult.status !== 0) process.exit(syncResult.status ?? 1);

if (!existsSync(apiRoutes)) {
  throw new Error(`Next.js API route directory not found: ${apiRoutes}`);
}
if (existsSync(temporarilyDisabledApiRoutes)) {
  throw new Error(`Refusing to overwrite ${temporarilyDisabledApiRoutes}`);
}
if (existsSync(temporarilyDisabledProxyEntry)) {
  throw new Error(`Refusing to overwrite ${temporarilyDisabledProxyEntry}`);
}
if (existsSync(temporarilyDisabledBootstrapEntry)) {
  throw new Error(`Refusing to overwrite ${temporarilyDisabledBootstrapEntry}`);
}

let movedApiRoutes = false;
let movedProxyEntry = false;
let movedBootstrapEntry = false;
try {
  // Static export cannot include dynamic Next.js API handlers. Keep the source
  // tree intact after building; Rust owns the same-origin API paths at runtime.
  renameSync(apiRoutes, temporarilyDisabledApiRoutes);
  movedApiRoutes = true;
  if (existsSync(proxyEntry)) {
    renameSync(proxyEntry, temporarilyDisabledProxyEntry);
    movedProxyEntry = true;
  }
  if (existsSync(bootstrapEntry)) {
    renameSync(bootstrapEntry, temporarilyDisabledBootstrapEntry);
    movedBootstrapEntry = true;
    writeFileSync(bootstrapEntry, "// Node-only runtime bootstrap is disabled for static export.\n");
  }

  const result = spawnSync(process.execPath, [nextCli, "build", "--webpack"], {
    cwd: projectRoot,
    env: { ...process.env, NINEROUTER_STATIC_BUILD: "true" },
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.signal) throw new Error(`Next.js build was interrupted by ${result.signal}`);
  if (result.status !== 0) process.exitCode = result.status ?? 1;
} finally {
  if (movedProxyEntry) renameSync(temporarilyDisabledProxyEntry, proxyEntry);
  if (movedBootstrapEntry) {
    if (existsSync(bootstrapEntry)) unlinkSync(bootstrapEntry);
    renameSync(temporarilyDisabledBootstrapEntry, bootstrapEntry);
  }
  if (movedApiRoutes) renameSync(temporarilyDisabledApiRoutes, apiRoutes);
}
