"use client";

import { useEffect } from "react";

export default function InitPage() {
  useEffect(() => {
    window.location.replace("/dashboard/");
  }, []);

  return <main className="p-8 text-sm text-text-muted">Opening dashboard...</main>;
}
