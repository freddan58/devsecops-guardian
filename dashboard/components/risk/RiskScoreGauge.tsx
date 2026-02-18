"use client";

import { riskScoreColor } from "@/lib/utils";

interface RiskScoreGaugeProps {
  score: number;
  level: string;
  size?: number;
}

export function RiskScoreGauge({ score, level, size = 180 }: RiskScoreGaugeProps) {
  const color = riskScoreColor(score);
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius; // half circle
  const progress = (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 20} viewBox={`0 0 ${size} ${size / 2 + 20}`}>
        {/* Background arc */}
        <path
          d={`M ${10} ${size / 2 + 10} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2 + 10}`}
          fill="none"
          stroke="#2a2a4e"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d={`M ${10} ${size / 2 + 10} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2 + 10}`}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
        {/* Score text */}
        <text
          x={center}
          y={size / 2 - 5}
          textAnchor="middle"
          className="fill-white text-3xl font-bold"
          style={{ fontSize: "2rem" }}
        >
          {score}
        </text>
        <text
          x={center}
          y={size / 2 + 15}
          textAnchor="middle"
          style={{ fill: color, fontSize: "0.75rem", fontWeight: 600 }}
        >
          {level}
        </text>
      </svg>
    </div>
  );
}
