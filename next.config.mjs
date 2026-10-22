import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const projectRoot = dirname(fileURLToPath(import.meta.url));
// CLI bundling needs workspace root so tracing includes hoisted node_modules (slim ~50MB).
// Docker / default uses projectRoot so server.js lands at /app/server.js (not nested).
const tracingRoot = process.env.NEXT_TRACING_ROOT_MODE === "workspace"
  ? join(projectRoot, "..")
  : projectRoot;
const proxyClientMaxBodySize = process.env.NINEROUTER_PROXY_CLIENT_MAX_BODY_SIZE || "128mb";
const routeInferenceThroughRust = process.env.NINEROUTER_RUST_ENABLED === "true";
const staticFrontendBuild = process.env.NINEROUTER_STATIC_BUILD === "true";

/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: process.env.NEXT_DIST_DIR || ".next",
  output: staticFrontendBuild ? "export" : "standalone",
  trailingSlash: staticFrontendBuild,
  // `open` must stay external. It derives its own directory from `import.meta.url`, and
  // webpack replaces that with the absolute path of the BUILD machine as a string literal.
  // A release built on macOS therefore ships `file:///Users/.../open/index.js`, which
  // `fileURLToPath` rejects on Windows ("File URL path must be absolute" — no drive
  // letter). That throw happens at module scope, so every consumer of `open` dies on
  // import — including xAI/Grok token refresh, which loads the OAuth service that imports
  // it. Keeping it external preserves the real `import.meta.url` at runtime.
  // @aws-sdk/credential-providers must stay external for the same class of reason: it reads
  // ~/.aws/config and the SSO token cache from disk at runtime and resolves its credential
  // plugins by dynamic require, neither of which survives bundling.
  serverExternalPackages: ["better-sqlite3", "sql.js", "node:sqlite", "bun:sqlite", "open", "@aws-sdk/credential-providers"],
  turbopack: {
    root: tracingRoot
  },
  outputFileTracingRoot: tracingRoot,
  outputFileTracingExcludes: {
    "*": ["./gitbook/**/*"]
  },
  images: {
    unoptimized: true
  },
  env: {
    NEXT_PUBLIC_NINEROUTER_RUST_ENABLED: routeInferenceThroughRust || staticFrontendBuild ? "true" : "false",
  },
  experimental: {
    // #1529/#1572: LLM clients can send long context or base64 image payloads through /v1 rewrites.
    proxyClientMaxBodySize,
    // Cache fetch responses across HMR refreshes for faster dev reloads.
    serverComponentsHmrCache: true,
    // Tree-shake heavy barrel imports to cut compile + bundle size
    optimizePackageImports: ["@xyflow/react", "@dnd-kit/core", "@dnd-kit/sortable", "material-symbols", "marked"],
  },
  webpack: (config, { isServer }) => {
    if (staticFrontendBuild && isServer) {
      const staticBuildNoop = join(projectRoot, "src/static-build/noop.js");
      config.resolve.alias = {
        ...config.resolve.alias,
        "@/lib/network/initOutboundProxy": staticBuildNoop,
        "@/shared/services/bootstrap": staticBuildNoop,
        "@/lib/consoleLogBuffer": staticBuildNoop,
      };
    }
    // Ignore fs/path modules in browser bundle
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
      };
    }
    // Exclude non-source dirs from watcher to reduce inotify load
    config.watchOptions = {
      ...config.watchOptions,
      aggregateTimeout: 300,
      ignored: /[\\/](node_modules|\.git|logs|\.next|\.next-cli-build|gitbook|cli|open-sse\.old|tests|docs)[\\/]/,
    };
    return config;
  },
  ...(staticFrontendBuild ? {} : {
    async rewrites() {
    const rustRoutes = routeInferenceThroughRust ? [
      { source: "/v1/:path*", destination: "/api/rust/v1/:path*" },
      { source: "/v1", destination: "/api/rust/v1" },
      { source: "/api/v1/:path*", destination: "/api/rust/v1/:path*" },
      { source: "/api/v1", destination: "/api/rust/v1" },
      { source: "/codex/:path*", destination: "/api/rust/v1/responses" },
      { source: "/responses", destination: "/api/rust/v1/responses" },
      { source: "/systemone", destination: "/api/rust/v1/systemone" },
      { source: "/api/providers/client", destination: "/api/rust/api/providers/client" },
      { source: "/api/providers", destination: "/api/rust/api/providers" },
      { source: "/api/providers/:id", destination: "/api/rust/api/providers/:id" },
      { source: "/api/auth/oidc/test", destination: "/api/rust/api/auth/oidc/test" },
      { source: "/api/auth/oidc/start", destination: "/api/rust/api/auth/oidc/start" },
      { source: "/api/auth/oidc/callback", destination: "/api/rust/api/auth/oidc/callback" },
      { source: "/api/auth/saml/test", destination: "/api/rust/api/auth/saml/test" },
      { source: "/api/auth/saml/metadata", destination: "/api/rust/api/auth/saml/metadata" },
      { source: "/api/cli-tools/cowork-mcp-registry", destination: "/api/rust/api/cli-tools/cowork-mcp-registry" },
      { source: "/api/cli-tools/cowork-mcp-tools", destination: "/api/rust/api/cli-tools/cowork-mcp-tools" },
      { source: "/api/media-providers/tts/voices", destination: "/api/rust/api/media-providers/tts/voices" },
      { source: "/api/provider-nodes", destination: "/api/rust/api/provider-nodes" },
      { source: "/api/provider-nodes/:id", destination: "/api/rust/api/provider-nodes/:id" },
      { source: "/api/usage/logs", destination: "/api/rust/api/usage/logs" },
      { source: "/api/usage/request-logs", destination: "/api/rust/api/usage/request-logs" },
      ...["history", "stats", "chart", "providers", "request-details", "stream"].map((path) => ({
        source: `/api/usage/${path}`,
        destination: `/api/rust/api/usage/${path}`,
      })),
      { source: "/api/usage/:connectionId/codex-reset-credits", destination: "/api/rust/api/usage/:connectionId/codex-reset-credits" },
      { source: "/api/usage/:connectionId", destination: "/api/rust/api/usage/:connectionId" },
      { source: "/api/proxy-pools", destination: "/api/rust/api/proxy-pools" },
      { source: "/api/proxy-pools/:id/test", destination: "/api/rust/api/proxy-pools/:id/test" },
      { source: "/api/proxy-pools/:id", destination: "/api/rust/api/proxy-pools/:id" },
      ...["load", "save", "translate", "send"].map((path) => ({
        source: `/api/translator/${path}`,
        destination: `/api/rust/api/translator/${path}`,
      })),
      { source: "/api/translator/console-logs", destination: "/api/rust/api/translator/console-logs" },
      { source: "/api/translator/console-logs/stream", destination: "/api/rust/api/translator/console-logs/stream" },
      ...["deepgram", "elevenlabs", "inworld", "minimax"].map((provider) => ({
        source: `/api/media-providers/tts/${provider}/voices`,
        destination: `/api/rust/api/media-providers/tts/${provider}/voices`,
      })),
      { source: "/api/mcp/:plugin/sse", destination: "/api/rust/api/mcp/:plugin/sse" },
      { source: "/api/mcp/:plugin/message", destination: "/api/rust/api/mcp/:plugin/message" },
      ...["combos", "keys", "models", "models/alias", "models/custom", "models/disabled", "settings", "pricing", "version"].map((path) => ({
        source: `/api/${path}`,
        destination: `/api/rust/api/${path}`,
      })),
      ...["combos", "keys"].map((path) => ({
        source: `/api/${path}/:id`,
        destination: `/api/rust/api/${path}/:id`,
      })),
    ] : [];
    const nodeRoutes = [
      {
        source: "/v1/v1/:path*",
        destination: "/api/v1/:path*"
      },
      {
        source: "/v1/v1",
        destination: "/api/v1"
      },
      {
        source: "/codex/:path*",
        destination: "/api/v1/responses"
      },
      {
        source: "/responses",
        destination: "/api/v1/responses"
      },
      {
        source: "/systemone",
        destination: "/api/v1/systemone"
      },
      {
        source: "/v1beta/:path*",
        destination: "/api/v1beta/:path*"
      },
      {
        source: "/v1beta",
        destination: "/api/v1beta"
      },
      {
        source: "/v1/:path*",
        destination: "/api/v1/:path*"
      },
      {
        source: "/v1",
        destination: "/api/v1"
      }
    ];
      return {
        beforeFiles: rustRoutes,
        afterFiles: nodeRoutes,
        fallback: [],
      };
    }
  }),
};

export default nextConfig;
