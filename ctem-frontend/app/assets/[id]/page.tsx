"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { Asset, OpenPort, BlastRadiusDetail } from "@/lib/types";
import { Badge } from "@/components/Badge";

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;

  const [asset, setAsset] = useState<Asset | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusDetail | null>(null);
  const [explanations, setExplanations] = useState<any[]>([]);
  const [changes, setChanges] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [criticality, setCriticality] = useState("low");
  const [zone, setZone] = useState("internal");
  const [hostname, setHostname] = useState("");
  const [assetType, setAssetType] = useState("server");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [assetId]);

  async function load() {
    try {
      const assetResult = await api.getAsset(assetId);
      if (!assetResult) return;
      setAsset(assetResult);
      setCriticality(assetResult.criticality || "low");
      setZone(assetResult.zone || "internal");
      setHostname(assetResult.hostname || "");
      setAssetType(assetResult.asset_type || "server");

      try {
        const explainResult = await api.explainAssetRisk(assetId);
        setExplanations(explainResult?.explanations || []);
      } catch {
        setExplanations([]);
      }

      try {
        const changesResult = await api.getAssetChanges(assetId);
        setChanges(changesResult?.changes || []);
      } catch {
        setChanges([]);
      }

      try {
        const brResult = await api.getAssetBlastRadius(assetId);
        setBlastRadius(brResult);
      } catch {
        setBlastRadius(null);
      }
    } catch (err) {
      console.warn("Failed to load asset details:", err);
    } finally {
      setLoading(false);
    }
  }

  async function confirmAsset() {
    try {
      await api.confirmAsset(assetId);
      await load();
    } catch (err) {
      console.error("Failed to confirm asset:", err);
    }
  }

  async function saveMetadata() {
    setSaving(true);
    try {
      await api.editAsset(assetId, {
        criticality,
        zone,
        hostname: hostname || null,
        asset_type: assetType,
      });
      setIsEditing(false);
      load();
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (!window.confirm("Are you sure you want to delete this asset?")) return;
    await api.deleteAsset(assetId);
    router.push("/assets");
  }

  if (loading || !asset) return <p className="text-gray-400">Loading asset details...</p>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{asset.hostname || asset.ip_address || asset.id}</h1>
          <p className="text-sm text-gray-400">
            Type: <span className="font-mono text-gray-200">{asset.asset_type || "unknown"}</span> • ID:{" "}
            <span className="font-mono text-xs text-gray-500">{asset.id}</span>
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => load()}
            className="px-3 py-1.5 text-sm rounded border border-gray-700 hover:bg-gray-800 text-gray-200"
            title="Refresh asset state and change history"
          >
            🔄 Refresh
          </button>
          {asset.asset_status === "discovered" && (
            <button onClick={confirmAsset} className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white font-medium">
              Confirm Asset
            </button>
          )}
          <button
            onClick={() => setIsEditing(!isEditing)}
            className="px-3 py-1.5 text-sm rounded border border-gray-700 hover:bg-gray-800 text-gray-200"
          >
            {isEditing ? "Cancel Edit" : "Edit Asset"}
          </button>
          <button onClick={remove} className="px-3 py-1.5 text-sm rounded border border-red-800 hover:bg-red-900/40 text-red-400">
            Delete
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <InfoCard label="Status" value={<Badge value={asset.asset_status} />} />
        <InfoCard label="Zone" value={<span className="font-mono text-xs">{asset.zone || "-"}</span>} />
        <InfoCard label="IP Address" value={<span className="font-mono text-xs">{asset.ip_address || "-"}</span>} />
        <InfoCard label="Criticality" value={<Badge value={asset.criticality} />} />
      </div>

      {isEditing && (
        <div className="bg-gray-900 border border-blue-900/60 rounded p-4 space-y-4">
          <h2 className="text-sm font-semibold text-blue-400">Edit Asset Properties</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Hostname</label>
              <input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Asset Type</label>
              <input
                value={assetType}
                onChange={(e) => setAssetType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Zone</label>
              <select
                value={zone}
                onChange={(e) => setZone(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              >
                <option value="external">External</option>
                <option value="internal">Internal</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Criticality</label>
              <select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              >
                {["low", "medium", "high", "critical"].map((lvl) => (
                  <option key={lvl} value={lvl}>
                    {lvl}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={() => setIsEditing(false)} className="px-3 py-1.5 text-xs rounded border border-gray-700 text-gray-300">
              Cancel
            </button>
            <button
              onClick={saveMetadata}
              disabled={saving}
              className="px-3 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white font-medium"
            >
              {saving ? "Saving..." : "Save Changes"}
            </button>
          </div>
        </div>
      )}

      <div>
        <h2 className="text-lg font-semibold mb-3">Open Ports & Services</h2>
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Port</th>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Service</th>
                <th className="px-4 py-2">Product</th>
                <th className="px-4 py-2">Version</th>
              </tr>
            </thead>
            <tbody>
              {(asset.open_ports || []).map((port: OpenPort, idx: number) => (
                <tr key={idx} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2 font-mono font-semibold text-blue-400">{port.port}</td>
                  <td className="px-4 py-2 text-gray-400 uppercase text-xs">{port.protocol}</td>
                  <td className="px-4 py-2 text-gray-200">{port.service || "-"}</td>
                  <td className="px-4 py-2 text-gray-300">{port.product || "-"}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{port.version || "-"}</td>
                </tr>
              ))}
              {(!asset.open_ports || asset.open_ports.length === 0) && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-500">
                    No open ports detected for this asset.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {blastRadius && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-gray-800 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg">💥</span>
                <h2 className="text-lg font-semibold text-gray-100">Blast Radius & Lateral Reachability</h2>
                <span
                  className={`px-2 py-0.5 text-xs font-bold rounded ${
                    blastRadius.exposure_level === "Catastrophic"
                      ? "bg-red-950 text-red-400 border border-red-800"
                      : blastRadius.exposure_level === "High"
                      ? "bg-orange-950 text-orange-400 border border-orange-800"
                      : "bg-blue-950 text-blue-400 border border-blue-800"
                  }`}
                >
                  {blastRadius.exposure_level}
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                If this asset is compromised, an attacker can pivot to{" "}
                <strong className="text-gray-200">{blastRadius.total_affected_count} collateral assets</strong> across subnets, zones, and service dependencies.
              </p>
            </div>
            <Link
              href={`/blast-radius?assetId=${asset.id}`}
              className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5 self-start md:self-auto"
            >
              <span>Explore Graph & Containment →</span>
            </Link>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Blast Radius Multiplier</span>
              <span className="text-xl font-extrabold text-red-400 mt-1 block">
                {blastRadius.blast_radius_multiplier}x
              </span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Direct 1st-Hop Targets</span>
              <span className="text-xl font-bold text-gray-200 mt-1 block">
                {blastRadius.direct_reachable_count} systems
              </span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Critical Assets Exposed</span>
              <span className="text-xl font-bold text-amber-400 mt-1 block">
                {blastRadius.criticality_breakdown.critical} critical
              </span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Cascade 2nd-Hop Targets</span>
              <span className="text-xl font-bold text-blue-400 mt-1 block">
                {blastRadius.cascade_reachable_count} systems
              </span>
            </div>
          </div>

          {blastRadius.recommendations && blastRadius.recommendations.length > 0 && (
            <div className="bg-gray-950/60 border border-gray-800/80 rounded-lg p-3 text-xs space-y-1">
              <span className="font-semibold text-gray-300 block">Containment Directive:</span>
              <p className="text-gray-400">{blastRadius.recommendations[0]}</p>
            </div>
          )}
        </div>
      )}

      <div>
        <h2 className="text-lg font-semibold mb-3">Why this asset is vulnerable</h2>
        <div className="space-y-3">
          {explanations.map((exp, idx) => (
            <div key={idx} className="bg-gray-900 border border-gray-800 rounded p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-sm text-blue-400 font-medium">{exp.cve_id}</span>
                <div className="flex gap-2 items-center">
                  {exp.criticality_mismatch && <Badge value="critical" />}
                  <Badge value={exp.priority_tier} />
                  <span className="text-sm font-semibold text-gray-300">score {exp.composite_score}</span>
                </div>
              </div>
              <p className="text-sm text-gray-300">{exp.reason}</p>
            </div>
          ))}
          {explanations.length === 0 && (
            <p className="text-gray-500 text-sm bg-gray-900 border border-gray-800 rounded p-4">
              No vulnerabilities or CVE findings associated with this asset yet.
            </p>
          )}
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Change History</h2>
          <span className="text-xs text-gray-400">{changes.length} recorded event(s)</span>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Change Type</th>
                <th className="px-4 py-2">Previous</th>
                <th className="px-4 py-2">New</th>
                <th className="px-4 py-2">Detected</th>
              </tr>
            </thead>
            <tbody>
              {changes.map((change) => (
                <tr key={change.id} className="border-t border-gray-800">
                  <td className="px-4 py-2 text-gray-400 font-mono text-xs">{change.change_type}</td>
                  <td className="px-4 py-2">{change.previous_value || "-"}</td>
                  <td className="px-4 py-2">{change.new_value || "-"}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{new Date(change.detected_at).toLocaleString()}</td>
                </tr>
              ))}
              {changes.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                    No drift or port changes recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded p-3">
      <p className="text-xs text-gray-500">{label}</p>
      <div className="mt-1 text-sm font-medium">{value}</div>
    </div>
  );
}
