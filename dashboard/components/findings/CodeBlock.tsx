"use client";

import { useEffect, useRef } from "react";
import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import python from "highlight.js/lib/languages/python";
import json from "highlight.js/lib/languages/json";
import "highlight.js/styles/github-dark.css";

// Register languages
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("python", python);
hljs.registerLanguage("json", json);

interface CodeBlockProps {
  code: string;
  language?: string;
  highlightLine?: number;
  startLine?: number;
  fileName?: string;
}

export function CodeBlock({
  code,
  language = "javascript",
  highlightLine,
  startLine = 1,
  fileName,
}: CodeBlockProps) {
  const codeRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (codeRef.current) {
      hljs.highlightElement(codeRef.current);
    }
  }, [code, language]);

  const lines = code.split("\n");

  return (
    <div className="rounded-lg overflow-hidden border border-[#2a2a4e]">
      {fileName && (
        <div className="px-4 py-2 bg-[#1a1a2e] border-b border-[#2a2a4e] flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
          <span className="text-xs text-slate-400 mono">{fileName}</span>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <tbody>
            {lines.map((line, i) => {
              const lineNum = startLine + i;
              const isHighlighted = highlightLine === lineNum;
              return (
                <tr
                  key={i}
                  className={isHighlighted ? "bg-red-500/20" : "hover:bg-white/5"}
                >
                  <td className="px-3 py-0 text-right text-xs text-slate-600 select-none w-10 border-r border-[#2a2a4e]">
                    {lineNum}
                  </td>
                  <td className="px-4 py-0">
                    <pre className="!bg-transparent !p-0 !m-0">
                      <code
                        ref={i === 0 ? codeRef : undefined}
                        className={`language-${language} !bg-transparent`}
                      >
                        {line || " "}
                      </code>
                    </pre>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
