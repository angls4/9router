import { NextResponse } from "next/server";

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

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      duplex: "half",
      redirect: "manual",
      cache: "no-store",
    });
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
