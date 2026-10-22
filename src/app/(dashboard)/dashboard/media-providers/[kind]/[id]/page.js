import { Suspense } from "react";
import ClientPage from "./ClientPage";
import { AI_PROVIDERS, MEDIA_PROVIDER_KINDS } from "@/shared/constants/providers";

export const dynamicParams = false;

export function generateStaticParams() {
  const validKinds = new Set(MEDIA_PROVIDER_KINDS.map(({ id }) => id));
  const params = Object.entries(AI_PROVIDERS).flatMap(([id, provider]) =>
    (provider.serviceKinds ?? ["llm"])
      .filter((kind) => validKinds.has(kind))
      .map((kind) => ({ kind, id })),
  );
  params.push({ kind: "embedding", id: "custom" });
  return params;
}

export default function MediaProviderDetailPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-sm text-text-muted">Loading...</div>}>
      <ClientPage />
    </Suspense>
  );
}
