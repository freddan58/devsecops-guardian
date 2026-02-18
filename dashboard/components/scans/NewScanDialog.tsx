"use client";

import { useState } from "react";
import { createScan } from "@/lib/api";

interface NewScanDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

export function NewScanDialog({ open, onClose, onCreated }: NewScanDialogProps) {
  const [repoPath, setRepoPath] = useState("demo-app");
  const [dryRun, setDryRun] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await createScan({
        repository_path: repoPath,
        dry_run: dryRun,
      });
      onCreated();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-md mx-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">New Security Scan</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">
              Repository Path
            </label>
            <input
              type="text"
              value={repoPath}
              onChange={(e) => setRepoPath(e.target.value)}
              placeholder="demo-app"
              className="w-full px-3 py-2 rounded-lg bg-[#0a0a0f] border border-[#2a2a4e] text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 text-sm"
            />
            <p className="mt-1 text-xs text-slate-500">
              Path within the repository to scan (e.g., &quot;demo-app&quot;)
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="dry-run"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
              className="rounded border-[#2a2a4e] bg-[#0a0a0f] text-blue-600"
            />
            <label htmlFor="dry-run" className="text-sm text-slate-300">
              Dry run (skip GitHub writes)
            </label>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border border-[#2a2a4e] text-slate-300 hover:bg-white/5 text-sm font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !repoPath.trim()}
              className="flex-1 px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium transition-colors"
            >
              {loading ? "Starting..." : "Start Scan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
