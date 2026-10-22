import { Suspense } from "react";
import { AI_PROVIDERS } from "@/shared/constants/providers";
import ClientPage from "./ClientPage";

export const dynamicParams = false;

export function generateStaticParams() {
  return [
    ...Object.keys(AI_PROVIDERS).map((id) => ({ id })),
    { id: "custom" },
  ];
}

export default function ProviderDetailPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-sm text-text-muted">Loading...</div>}>
      <ClientPage />
    </Suspense>
  );
}
