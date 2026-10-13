"use client";

import { useState } from "react";
import { api } from "@/lib/api";

const TARGET_TYPES = ["domain", "ip", "cidr", "cloud_project"];

export function NewScanModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("domain");
  const [businessUnit, setBusinessUnit] = useState("");
  const [criticalityHint, setCriticalityHint] = useState("low");
  const [error, setError] = useState<string | null>(null);
  const [existingWarning, setExistingWarning] = useState<any>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(forceNew = false) {
    setSubmitting(true);
    setError(null);
    try {
      const labels = businessUnit ? { business_unit: businessUnit, criticality_hint: criticalityHint } : { criticality_hint: criticalityHint };
      const result = await api.createScan(target, targetType, labels, undefined, forceNew);
      if (result.existing && !forceNew) {
        setExistingWarning(result.scan);
        setSubmitting(false);
        return;
      }
      onCreated();
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold mb-4">New Scan Target</h2>

        {existingWarning ? (
          <div className="space-y-4">
            <div className="bg-yellow-900/30 border border-yellow-700 rounded p-3 text-sm text-yellow-200">
              This target was already scanned on {new Date(existingWarning.created_at).toLocaleString()}
              {" "}(status: {existingWarning.status}). Start a new scan anyway?
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => setExistingWarning(null)} className="px-3 py-1.5 text-sm rounded border border-gray-700 text-gray-300">
                Back
              </button>
              <button onClick={() => submit(true)} disabled={submitting} className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white">
                Scan Anyway
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Target</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com, 10.0.0.5, 10.0.0.0/24, my-gcp-project"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Target Type</label>
              <select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                {TARGET_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Business Unit (optional)</label>
              <input
                value={businessUnit}
                onChange={(e) => setBusinessUnit(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Criticality Hint</label>
              <select
                value={criticalityHint}
                onChange={(e) => setCriticalityHint(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                {["low", "medium", "high", "critical"].map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>

            {error && <p className="text-red-400 text-sm">{error}</p>}

            <div className="flex justify-end gap-2 pt-2">
              <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-gray-700 text-gray-300">
                Cancel
              </button>
              <button
                onClick={() => submit(false)}
                disabled={submitting || !target}
                className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white disabled:opacity-50"
              >
                {submitting ? "Submitting..." : "Start Scan"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
