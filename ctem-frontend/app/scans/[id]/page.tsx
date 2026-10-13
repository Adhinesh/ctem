"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { Scan, Asset } from "@/lib/types";
import { Badge } from "@/components/Badge";

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    loadScan();
    const interval = setInterval(loadScan, 3000);
    return () => clearInterval(interval);
  }, [scanId]);

  async function loadScan() {
    try {
      const scanResult = await api.getScan(scanId);
      setScan(scanResult);
      const assetsResult = await api.getScanAssets(scanId);
      setAssets(assetsResult.assets || []);
    } catch (err) {
      console.error("Failed to load scan:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRescan() {
    setRescanning(true);
    try {
      await api.rescan(scanId);
      await loadScan();
    } catch (err: any) {
      alert("Failed to start rescan: " + (err.message || String(err)));
    } finally {
      setRescanning(false);
    }
  }

  async function handleDelete() {
    if (!confirm("Are you sure you want to delete this scan record?")) return;
    setDeleting(true);
    try {
      await api.deleteScan(scanId);
      router.push("/scans");
    } catch (err) {
      alert("Failed to delete scan");
      setDeleting(false);
    }
  }

  if (loading || !scan) return <p className="text-gray-400">Loading scan details...</p>;

  const isActive = ["queued", "running", "ingesting", "scoring"].includes(scan.status);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold">{scan.target}</h1>
            <Badge value={scan.status} />
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Type: <span className="text-gray-300 font-mono">{scan.target_type}</span> • Created:{" "}
            <span className="text-gray-300">{new Date(scan.created_at).toLocaleString()}</span>
            {scan.finished_at && (
              <>
                {" "}
                • Finished: <span className="text-gray-300">{new Date(scan.finished_at).toLocaleString()}</span>
              </>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!isActive && (
            <button
              onClick={handleRescan}
              disabled={rescanning}
              className="px-3 py-1.5 text-xs rounded border border-blue-700 bg-blue-950/40 text-blue-300 hover:bg-blue-900/60 font-medium"
            >
              {rescanning ? "Starting..." : "🔄 Rescan Target"}
            </button>
          )}
          {isActive && (
            <button
              onClick={async () => {
                await api.cancelScan(scanId);
                loadScan();
              }}
              className="px-3 py-1.5 text-xs rounded border border-yellow-700 bg-yellow-950/40 text-yellow-300 hover:bg-yellow-900/60 font-medium"
            >
              Cancel Scan
            </button>
          )}
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="px-3 py-1.5 text-xs rounded border border-red-800 bg-red-950/30 text-red-400 hover:bg-red-900/50 disabled:opacity-50"
          >
            {deleting ? "Deleting..." : "Delete Scan"}
          </button>
        </div>
      </div>

      {isActive && (
        <div className="bg-blue-950/30 border border-blue-800/60 rounded p-4 flex items-center gap-3 text-sm text-blue-300">
          <div className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-ping" />
          <span>Scan pipeline actively executing (Recon / Port Discovery / CVE Correlation / Risk Scoring)...</span>
        </div>
      )}

      {scan.error_message && (
        <div className="bg-red-950/30 border border-red-800/60 rounded p-4 text-sm text-red-300">
          <p className="font-semibold mb-1">Scan Error:</p>
          <p className="font-mono text-xs">{scan.error_message}</p>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Discovered Assets ({assets.length})</h2>
          <span className="text-xs text-gray-400">Click any asset to inspect open ports and CVE vulnerability details</span>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2.5">Hostname / IP</th>
                <th className="px-4 py-2.5">Zone</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">Criticality</th>
                <th className="px-4 py-2.5 text-center">Open Ports</th>
                <th className="px-4 py-2.5">Risk Tier</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2.5">
                    <Link href={`/assets/${asset.id}`} className="text-blue-400 hover:underline font-mono">
                      {asset.hostname || asset.ip_address || asset.id}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-gray-400">{asset.zone || "-"}</td>
                  <td className="px-4 py-2.5 text-gray-400 capitalize">{asset.asset_type || "external"}</td>
                  <td className="px-4 py-2.5 text-gray-300 capitalize">{asset.criticality || "medium"}</td>
                  <td className="px-4 py-2.5 text-center">
                    <span className="font-mono bg-gray-800 px-2 py-0.5 rounded text-xs text-gray-300">
                      {asset.open_ports_count ?? 0}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    {asset.highest_tier ? (
                      <Badge value={asset.highest_tier} />
                    ) : (
                      <span className="text-gray-500 text-xs">-</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge value={asset.asset_status} />
                  </td>
                </tr>
              ))}
              {assets.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                    {isActive ? "Scan in progress, discovering hosts and services..." : "No assets discovered in this scan."}
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
