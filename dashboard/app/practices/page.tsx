"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getScans } from "@/lib/api";

export default function PracticesRedirect() {
  const router = useRouter();
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const scans = await getScans();
        const completed = scans.filter((s) => s.status === "COMPLETED");
        if (completed.length > 0) {
          router.replace(`/scans/${completed[0].id}/practices`);
        } else {
          setError("No completed scans found. Run a scan first to see best practices.");
        }
      } catch {
        setError("Failed to load scans.");
      }
    })();
  }, [router]);

  if (error) {
    return (
      <div className="p-6">
        <div className="card text-center py-12">
          <p className="text-slate-400">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 text-center text-slate-400">
      Loading best practices...
    </div>
  );
}
