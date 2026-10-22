import { Suspense } from "react";
import ClientPage from "./ClientPage";

export const dynamicParams = false;

export function generateStaticParams() {
  return [{ id: "custom" }];
}

export default function ComboDetailPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-sm text-text-muted">Loading...</div>}>
      <ClientPage />
    </Suspense>
  );
}
