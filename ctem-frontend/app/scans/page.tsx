"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Scan } from "@/lib/types";
import { Badge } from "@/components/Badge";
import { NewScanModal } from "@/components/NewScanModal";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [rescanningId, setRescanningId] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 4000);
    return () => clearInterval(interval);
  }, []);

  async function loadScans() {
    try {
      const result = await api.getScanHistory();
      setScans(result.history || []);
    } catch (err) {
      console.warn("Failed to load scans:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRescan(scanId: string) {
    setRescanningId(scanId);
    try {
      await api.rescan(scanId);
      await loadScans();
    } catch (err: any) {
      alert("Failed to start rescan: " + (err.message || String(err)));
    } finally {
      setRescanningId(null);
    }
  }

  async function deleteScan(scanId: string) {
    if (!window.confirm("Delete this scan record?")) return;
    try {
      await api.deleteScan(scanId);
      await loadScans();
    } catch (err) {
      console.error("Failed to delete scan:", err);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Security Scans</h1>
          <p className="text-xs text-gray-400">External attack surface discovery, network port probes, and vulnerability scoring.</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded font-medium"
        >
          + New Scan
        </button>
      </div>

      {loading ? (
        <p className="text-gray-400">Loading scan history...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Target Type</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Started</th>
                <th className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const isActive = ["queued", "running", "ingesting", "scoring"].includes(scan.status);
                const isThisRescanning = rescanningId === scan.scan_id;

                return (
                  <tr key={scan.scan_id} className="border-t border-gray-800 hover:bg-gray-800/50">
                    <td className="px-4 py-2">
                      <Link href={`/scans/${scan.scan_id}`} className="text-blue-400 hover:underline font-medium">
                        {scan.target}
                      </Link>
                    </td>
                    <td className="px-4 py-2 text-gray-400 font-mono text-xs">{scan.target_type}</td>
                    <td className="px-4 py-2">
                      <Badge value={scan.status} />
                    </td>
                    <td className="px-4 py-2 text-gray-500 text-xs">
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : "-"}
                    </td>
                    <td className="px-4 py-2 text-right space-x-2">
                      <button
                        onClick={() => handleRescan(scan.scan_id)}
                        disabled={isActive || isThisRescanning}
                        className="text-xs px-2.5 py-1 bg-blue-900/40 border border-blue-700/60 hover:bg-blue-800/60 text-blue-300 rounded font-medium disabled:opacity-40 disabled:cursor-not-allowed"
                        title="Rerun this scan in place without creating a new scan entry"
                      >
                        {isThisRescanning || isActive ? "Scanning..." : "Rescan"}
                      </button>
                      <Link
                        href={`/scans/${scan.scan_id}`}
                        className="text-xs px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded"
                      >
                        View
                      </Link>
                      <button
                        onClick={() => deleteScan(scan.scan_id)}
                        className="text-xs px-2.5 py-1 border border-red-900/50 text-red-400 hover:bg-red-950/40 rounded"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
              {scans.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-500">
                    No scans performed yet. Click &quot;+ New Scan&quot; to start.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showModal && <NewScanModal onClose={() => setShowModal(false)} onCreated={loadScans} />}
    </div>
  );
}
