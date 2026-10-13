"use client";

import { useState } from "react";
import { api } from "@/lib/api";

const ASSET_TYPES = ["endpoint", "server", "vps", "firewall", "computer", "laptop", "network_segment", "cloud_resource"];
const ZONES = ["internal", "external"];
const CRITICALITIES = ["low", "medium", "high", "critical"];

export function DeclareAssetModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [hostname, setHostname] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [assetType, setAssetType] = useState("server");
  const [zone, setZone] = useState("internal");
  const [criticality, setCriticality] = useState("medium");
  const [declaredBy, setDeclaredBy] = useState("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!hostname && !ipAddress) {
      setError("Hostname or IP Address is required");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await api.declareAssets(declaredBy, [
        {
          hostname: hostname.trim() || undefined,
          ip_address: ipAddress.trim() || undefined,
          asset_type: assetType,
          zone: zone,
          criticality: criticality,
        },
      ]);
      onCreated();
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to declare asset");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold mb-4">Declare Organizational Asset</h2>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Hostname</label>
            <input
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="e.g. prod-db-01, finance-laptop-05"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
            />
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-1">IP Address (optional)</label>
            <input
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="e.g. 10.0.1.25, 192.168.1.100"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Asset Type</label>
              <select
                value={assetType}
                onChange={(e) => setAssetType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                {ASSET_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Network Zone</label>
              <select
                value={zone}
                onChange={(e) => setZone(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                {ZONES.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Criticality</label>
              <select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Declared By</label>
              <input
                value={declaredBy}
                onChange={(e) => setDeclaredBy(e.target.value)}
                placeholder="e.g. it-admin, soc-lead"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
          </div>

          {error && <p className="text-red-400 text-sm">{error}</p>}

          <div className="flex justify-end gap-2 pt-3">
            <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-gray-700 text-gray-300">
              Cancel
            </button>
            <button
              onClick={submit}
              disabled={submitting || (!hostname && !ipAddress)}
              className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white disabled:opacity-50"
            >
              {submitting ? "Declaring..." : "Declare Asset"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
