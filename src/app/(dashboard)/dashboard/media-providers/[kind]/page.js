import ClientPage from "./ClientPage";
import { MEDIA_PROVIDER_KINDS } from "@/shared/constants/providers";

export const dynamicParams = false;

export function generateStaticParams() {
  return MEDIA_PROVIDER_KINDS.map(({ id }) => ({ kind: id }));
}

export default function MediaProviderKindPage() {
  return <ClientPage />;
}
