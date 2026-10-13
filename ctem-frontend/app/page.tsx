"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { HeatmapEntry, Alert, Asset, Scan } from "@/lib/types";
import { Badge } from "@/components/Badge";
import { RiskHeatmap } from "@/components/RiskHeatmap";

export default function DashboardPage() {
  const [heatmap, setHeatmap] = useState<HeatmapEntry[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [allAlerts, setAllAlerts] = useState<Alert[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [heatmapResult, openAlertsResult, allAlertsResult, assetsResult, scansResult] = await Promise.all([
        api.getHeatmap(),
        api.listAlerts({ status: "open" }),
        api.listAlerts(),
        api.listAssets(),
        api.getScanHistory(),
      ]);
      setHeatmap(heatmapResult?.heatmap || []);
      setAlerts(openAlertsResult?.alerts || []);
      setAllAlerts(allAlertsResult?.alerts || []);
      setAssets(assetsResult?.assets || []);
      setScans(scansResult?.scans || []);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function acknowledge(id: string) {
    try {
      await api.acknowledgeAlert(id);
      await loadData();
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  }

  async function resolve(id: string) {
    try {
      await api.resolveAlert(id);
      await loadData();
    } catch (err) {
      console.error("Failed to resolve alert:", err);
    }
  }

  const [rescoring, setRescoring] = useState(false);

  async function handleRescore() {
    setRescoring(true);
    try {
      await api.rescoreRisk();
      await loadData();
    } catch (err: any) {
      alert("Failed to rescore: " + err.message);
    } finally {
      setRescoring(false);
    }
  }

  const tierCounts = useMemo(() => {
    const counts: Record<string, number> = { P1: 0, P2: 0, P3: 0, P4: 0 };
    heatmap.forEach((entry) => {
      const tier = entry.priority_tier || "P4";
      if (counts[tier] !== undefined) {
        counts[tier] += entry.findings_count || 1;
      }
    });

    // Ensure critical assets are immediately reflected as P1
    const criticalCount = assets.filter((a) => a.criticality === "critical").length;
    if (criticalCount > counts["P1"]) {
      counts["P1"] = criticalCount;
    }

    return counts;
  }, [heatmap, assets]);

  if (loading) return <p className="text-gray-400">Loading dashboard...</p>;

  return (
    <div className="space-y-8">
      {error && <p className="text-red-400 text-sm">{error}</p>}

      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-semibold">Continuous Threat Exposure Overview</h1>
            <p className="text-sm text-gray-400">Prioritized risk exposure, active alerts, and host vulnerability posture</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleRescore}
              disabled={rescoring}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 text-sm rounded font-medium disabled:opacity-50 flex items-center gap-1.5"
            >
              <span>{rescoring ? "Scoring..." : "⚡ Rescore All"}</span>
            </button>
            <Link
              href="/blast-radius"
              className="px-3 py-1.5 bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-200 text-sm rounded font-medium flex items-center gap-1.5 transition"
            >
              <span>💥 Blast Radius</span>
            </Link>
            <Link href="/scans" className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded font-medium">
              + Run New Scan
            </Link>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div className="bg-gray-900 border border-gray-800 rounded p-4 col-span-2 md:col-span-2">
            <p className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Total Assets Monitored</p>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold text-gray-100">{assets.length}</span>
              <span className="text-xs text-gray-400">
                ({assets.filter((a) => a.zone === "external").length} external, {assets.filter((a) => a.zone === "internal").length} internal)
              </span>
            </div>
            <div className="flex items-center gap-3 mt-2 text-xs text-gray-400 border-t border-gray-800 pt-2">
              <span>
                <strong className="text-green-400 font-semibold">{assets.filter((a) => a.asset_confirmed || a.asset_status === "confirmed").length}</strong> Confirmed
              </span>
              <span>•</span>
              <span>
                <strong className="text-blue-400 font-semibold">{assets.filter((a) => a.asset_status === "discovered" && !a.asset_confirmed).length}</strong> Discovered
              </span>
              <span>•</span>
              <span>
                <strong className="text-red-400 font-semibold">{assets.filter((a) => a.criticality === "critical").length}</strong> Critical
              </span>
            </div>
          </div>

          {["P1", "P2", "P3", "P4"].map((tier) => (
            <div key={tier} className="bg-gray-900 border border-gray-800 rounded p-4">
              <div className="flex items-center justify-between">
                <Badge value={tier} />
                <span className="text-2xl font-bold">{tierCounts[tier] || 0}</span>
              </div>
              <p className="text-xs text-gray-500 mt-1">findings</p>
            </div>
          ))}
        </div>
      </div>

      {/* Lateral Blast Radius Callout Banner */}
      <div className="bg-gradient-to-r from-red-950/40 via-gray-900 to-gray-900 border border-red-900/40 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="text-2xl p-2 bg-red-950 rounded-lg border border-red-800/80">💥</span>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-gray-100">Lateral Blast Radius & Reachability Explorer</h3>
              <span className="text-[10px] bg-red-900/60 text-red-300 font-mono px-2 py-0.5 rounded border border-red-700/60">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-0.5">
              Simulate lateral movement propagation, collateral asset damage, and test subnet isolation/quarantine controls in real time.
            </p>
          </div>
        </div>
        <Link
          href="/blast-radius"
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-lg shadow transition whitespace-nowrap self-start md:self-auto"
        >
          Launch Blast Radius View →
        </Link>
      </div>

      {/* Threat Exposure Risk Matrix & Heatmap Component */}
      <RiskHeatmap heatmap={heatmap} assets={assets} scans={scans} alerts={allAlerts} />

      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xl font-semibold">Active Alerts & Anomaly Feed</h2>
          <span className="text-xs text-gray-500">{alerts.length} open alert(s)</span>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Title</th>
                <th className="px-4 py-2">Detected</th>
                <th className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 8).map((alert) => (
                <tr key={alert.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2">
                    <Badge value={alert.severity} />
                  </td>
                  <td className="px-4 py-2 text-gray-400 font-mono text-xs">{alert.alert_type}</td>
                  <td className="px-4 py-2">
                    <p className="font-medium text-gray-200">{alert.title}</p>
                    {alert.description && <p className="text-xs text-gray-400">{alert.description}</p>}
                  </td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{new Date(alert.created_at).toLocaleString()}</td>
                  <td className="px-4 py-2 text-right space-x-2">
                    <button
                      onClick={() => acknowledge(alert.id)}
                      className="text-xs px-2 py-1 border border-gray-700 rounded text-gray-300 hover:bg-gray-800"
                    >
                      Ack
                    </button>
                    <button
                      onClick={() => resolve(alert.id)}
                      className="text-xs px-2 py-1 bg-green-700 hover:bg-green-600 rounded text-white"
                    >
                      Resolve
                    </button>
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-500">
                    No active open alerts. All systems nominal.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-2 text-right">
          <Link href="/alerts" className="text-sm text-blue-400 hover:underline">
            View all alerts & history →
          </Link>
        </div>
      </div>
    </div>
  );
}
