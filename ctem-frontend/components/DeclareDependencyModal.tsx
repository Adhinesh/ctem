"use client";

import React, { useState } from "react";
import { Asset } from "@/lib/types";
import { api } from "@/lib/api";

interface DeclareDependencyModalProps {
  assets: Asset[];
  defaultSourceAssetId?: string;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function DeclareDependencyModal({
  assets,
  defaultSourceAssetId,
  isOpen,
  onClose,
  onSuccess,
}: DeclareDependencyModalProps) {
  const [sourceId, setSourceId] = useState(defaultSourceAssetId || (assets[0]?.id || ""));
  const [targetId, setTargetId] = useState(assets[1]?.id || (assets[0]?.id || ""));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!sourceId || !targetId) {
      setError("Please select both a source asset and a target dependency asset.");
      return;
    }
    if (sourceId === targetId) {
      setError("An asset cannot declare a dependency on itself.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      await api.createDependency(sourceId, targetId);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to create dependency link.");
    } finally {
      setLoading(false);
    }
  }

  const sourceAsset = assets.find((a) => a.id === sourceId);
  const targetAsset = assets.find((a) => a.id === targetId);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-5">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3">
          <div>
            <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
              <span>🔗</span> Declare Service Dependency
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Map architectural reliance between services to trace lateral movement and cascading impact.
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 text-lg leading-none p-1 rounded hover:bg-gray-800"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="bg-red-950/60 border border-red-800 text-red-300 px-3 py-2 rounded text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-gray-300 block mb-1.5">
              Source Asset (Relying System)
            </label>
            <select
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-blue-500"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname || a.ip_address || a.id} ({a.asset_type || "server"} • {a.zone || "zone"} • {a.criticality})
                </option>
              ))}
            </select>
          </div>

          {/* Visual Link Direction Indicator */}
          <div className="flex items-center justify-center gap-2 py-1 text-xs text-gray-400 font-mono">
            <span className="truncate max-w-[140px] text-blue-400 font-semibold">
              {sourceAsset?.hostname || sourceAsset?.ip_address || "Source"}
            </span>
            <span>──depends on──▶</span>
            <span className="truncate max-w-[140px] text-emerald-400 font-semibold">
              {targetAsset?.hostname || targetAsset?.ip_address || "Target"}
            </span>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-300 block mb-1.5">
              Target Asset (Upstream Service / Dependency)
            </label>
            <select
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-blue-500"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname || a.ip_address || a.id} ({a.asset_type || "server"} • {a.zone || "zone"} • {a.criticality})
                </option>
              ))}
            </select>
          </div>

          <div className="bg-gray-950 border border-gray-800 rounded p-3 text-xs text-gray-400 space-y-1">
            <p className="font-medium text-gray-300">Impact on Blast Radius:</p>
            <p>
              Establishing this edge will link both nodes in the Blast Radius attack graph and update the risk scoring engine with cross-asset reachability multipliers.
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-gray-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-800 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || sourceId === targetId}
              className="px-4 py-2 text-xs rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50 transition shadow"
            >
              {loading ? "Linking..." : "Establish Dependency"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
