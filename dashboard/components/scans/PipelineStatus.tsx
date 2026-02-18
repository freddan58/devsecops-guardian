"use client";

const STAGES = [
  { key: "scanner", label: "Scanner", icon: "1" },
  { key: "analyzer", label: "Analyzer", icon: "2" },
  { key: "fixer", label: "Fixer", icon: "3" },
  { key: "risk-profiler", label: "Risk Profiler", icon: "4" },
  { key: "compliance", label: "Compliance", icon: "5" },
];

interface PipelineStatusProps {
  stages: Record<string, string>;
  currentStage: string | null;
  status: string;
}

export function PipelineStatus({ stages, currentStage, status }: PipelineStatusProps) {
  return (
    <div className="flex items-center gap-1">
      {STAGES.map((stage, i) => {
        const stageStatus = stages[stage.key];
        const isRunning = currentStage === stage.key && status !== "COMPLETED" && status !== "FAILED";

        let bg = "bg-[#2a2a4e]";
        let text = "text-slate-500";
        let border = "border-[#2a2a4e]";

        if (stageStatus === "completed") {
          bg = "bg-green-500/20";
          text = "text-green-400";
          border = "border-green-500/30";
        } else if (stageStatus === "failed") {
          bg = "bg-red-500/20";
          text = "text-red-400";
          border = "border-red-500/30";
        } else if (isRunning || stageStatus === "running") {
          bg = "bg-blue-500/20";
          text = "text-blue-400";
          border = "border-blue-500/30";
        } else if (stageStatus === "skipped") {
          bg = "bg-gray-500/20";
          text = "text-gray-500";
          border = "border-gray-500/30";
        }

        return (
          <div key={stage.key} className="flex items-center">
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border ${bg} ${border} ${
                isRunning ? "pulse-glow" : ""
              }`}
              title={`${stage.label}: ${stageStatus || "pending"}`}
            >
              <span className={`text-xs font-bold ${text}`}>{stage.icon}</span>
              <span className={`text-xs font-medium ${text} hidden sm:inline`}>
                {stage.label}
              </span>
              {stageStatus === "completed" && (
                <svg className="w-3.5 h-3.5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
              )}
              {stageStatus === "failed" && (
                <svg className="w-3.5 h-3.5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                </svg>
              )}
            </div>
            {i < STAGES.length - 1 && (
              <div className={`w-4 h-px mx-0.5 ${
                stageStatus === "completed" ? "bg-green-500/40" : "bg-[#2a2a4e]"
              }`} />
            )}
          </div>
        );
      })}
    </div>
  );
}
