import { notFound } from "next/navigation";
import { CLI_TOOLS } from "@/shared/constants/cliTools";
import ToolDetailClient from "./ToolDetailClient";

export function generateStaticParams() {
  return Object.keys(CLI_TOOLS).map((toolId) => ({ toolId }));
}

export default async function ToolDetailPage({ params }) {
  const { toolId } = await params;
  if (!CLI_TOOLS[toolId]) notFound();
  return <ToolDetailClient toolId={toolId} />;
}
