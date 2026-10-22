import { NextResponse } from "next/server";
import { GET as getNodeUsage } from "../../usage/[connectionId]/route.js";
import {
  GET as getNodeCodexResetCredits,
  POST as postNodeCodexResetCredits,
} from "../../usage/[connectionId]/codex-reset-credits/route.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
]);

async function forward(request, context) {
  const { path = [] } = await context.params;
  const origin = (process.env.NINEROUTER_RUST_URL || "http://127.0.0.1:20128").replace(/\/+$/, "");
  const pathname = `/${path.map(encodeURIComponent).join("/")}`;
  const target = new URL(`${origin}${pathname}${new URL(request.url).search}`);
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!HOP_BY_HOP.has(name.toLowerCase())) headers.set(name, value);
  }
  // Dashboard requests have already passed Node's session guard. When the Rust
  // listener also has a gateway key configured, authenticate this local hop.
  if (path[0] === "api" && process.env.NINEROUTER_API_KEY) {
    headers.set("authorization", `Bearer ${process.env.NINEROUTER_API_KEY}`);
  }

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      duplex: "half",
      redirect: "manual",
      cache: "no-store",
    });
    if (
      response.status === 501 &&
      response.headers.get("x-9router-fallback") === "node" &&
      request.method === "POST" &&
      path[0] === "api" &&
      path[1] === "usage" &&
      path.length === 4 &&
      path[3] === "codex-reset-credits"
    ) {
      return postNodeCodexResetCredits(request, {
        params: Promise.resolve({ connectionId: path[2] }),
      });
    }
    if (
      response.status === 501 &&
      response.headers.get("x-9router-fallback") === "node" &&
      request.method === "GET" &&
      path[0] === "api" &&
      path[1] === "usage" &&
      path.length === 4 &&
      path[3] === "codex-reset-credits"
    ) {
      return getNodeCodexResetCredits(request, {
        params: Promise.resolve({ connectionId: path[2] }),
      });
    }
    if (
      response.status === 501 &&
      response.headers.get("x-9router-fallback") === "node" &&
      request.method === "GET" &&
      path[0] === "api" &&
      path[1] === "usage" &&
      path.length === 3
    ) {
      return getNodeUsage(request, {
        params: Promise.resolve({ connectionId: path[2] }),
      });
    }
    const responseHeaders = new Headers(response.headers);
    for (const name of HOP_BY_HOP) responseHeaders.delete(name);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error("Rust gateway proxy failed:", error?.message || error);
    return NextResponse.json({ error: { message: "Rust gateway unavailable", type: "proxy_error" } }, { status: 502 });
  }
}

export const GET = forward;
export const HEAD = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
export const OPTIONS = forward;
