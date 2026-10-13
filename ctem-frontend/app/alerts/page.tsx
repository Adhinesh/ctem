"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Alert } from "@/lib/types";
import { Badge } from "@/components/Badge";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [statusFilter, setStatusFilter] = useState("open");
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 10000);
    return () => clearInterval(interval);
  }, [statusFilter, severityFilter, typeFilter]);

  async function loadAlerts() {
    try {
      const filters: { status?: string; severity?: string; alert_type?: string } = {};
      if (statusFilter) filters.status = statusFilter;
      if (severityFilter) filters.severity = severityFilter;
      if (typeFilter) filters.alert_type = typeFilter;

      const result = await api.listAlerts(filters);
      setAlerts(result.alerts || []);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  }

  async function acknowledge(id: string) {
    try {
      await api.acknowledgeAlert(id);
      await loadAlerts();
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  }

  async function resolve(id: string) {
    try {
      await api.resolveAlert(id);
      await loadAlerts();
    } catch (err) {
      console.error("Failed to resolve alert:", err);
    }
  }

  const filteredAlerts = alerts.filter((alert) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      alert.title.toLowerCase().includes(q) ||
      (alert.description && alert.description.toLowerCase().includes(q)) ||
      alert.alert_type.toLowerCase().includes(q)
    );
  });

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const mediumCount = alerts.filter((a) => a.severity === "medium").length;
  const lowCount = alerts.filter((a) => a.severity === "low").length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Security Alerts</h1>
          <p className="text-sm text-gray-400">Continuous anomaly, drift, and severity alert monitoring</p>
        </div>
      </div>

      {/* Metrics Header */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded p-4">
          <p className="text-xs text-gray-400 uppercase tracking-wider font-semibold">Total Filtered</p>
          <p className="text-2xl font-bold mt-1 text-white">{filteredAlerts.length}</p>
        </div>
        <div className="bg-gray-900 border border-red-900/40 rounded p-4">
          <p className="text-xs text-red-400 uppercase tracking-wider font-semibold">Critical</p>
          <p className="text-2xl font-bold mt-1 text-red-400">{criticalCount}</p>
        </div>
        <div className="bg-gray-900 border border-orange-900/40 rounded p-4">
          <p className="text-xs text-orange-400 uppercase tracking-wider font-semibold">High</p>
          <p className="text-2xl font-bold mt-1 text-orange-400">{highCount}</p>
        </div>
        <div className="bg-gray-900 border border-yellow-900/40 rounded p-4">
          <p className="text-xs text-yellow-400 uppercase tracking-wider font-semibold">Medium / Low</p>
          <p className="text-2xl font-bold mt-1 text-yellow-300">{mediumCount + lowCount}</p>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="bg-gray-900 border border-gray-800 rounded p-4 flex flex-wrap items-center gap-3">
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search alert title or details..."
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm flex-1 min-w-[200px]"
        />

        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
          >
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="">All Statuses</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Severity:</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Type:</label>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
          >
            <option value="">All Types</option>
            <option value="asset_change">Asset Change (Port Drift)</option>
            <option value="log_severity">Log Severity (Security Onion)</option>
            <option value="ueba_anomaly">UEBA Anomaly (Identity)</option>
            <option value="peripheral_unauthorized">Peripheral Unauthorized</option>
            <option value="new_exposure">New Exposure</option>
          </select>
        </div>
      </div>

      {loading ? (
        <p className="text-gray-400">Loading alerts...</p>
      ) : (
        <div className="space-y-3">
          {filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`bg-gray-900 border rounded p-4 transition ${
                alert.severity === "critical"
                  ? "border-red-800/80 bg-red-950/10"
                  : alert.severity === "high"
                  ? "border-orange-800/60 bg-orange-950/10"
                  : "border-gray-800"
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge value={alert.severity} />
                    <span className="text-xs font-mono bg-gray-800 px-2 py-0.5 rounded text-gray-400">
                      {alert.alert_type}
                    </span>
                    <Badge value={alert.status} />
                  </div>
                  <p className="font-semibold text-white pt-1">{alert.title}</p>
                  {alert.description && (
                    <p className="text-sm text-gray-300 leading-relaxed">{alert.description}</p>
                  )}
                  <p className="text-xs text-gray-500 pt-1">
                    Created: {new Date(alert.created_at).toLocaleString()}
                  </p>
                </div>
                <div className="flex flex-col sm:flex-row gap-2 shrink-0">
                  {alert.status === "open" && (
                    <button
                      onClick={() => acknowledge(alert.id)}
                      className="text-xs px-3 py-1.5 border border-gray-700 hover:bg-gray-800 rounded text-gray-300 transition"
                    >
                      Acknowledge
                    </button>
                  )}
                  {alert.status !== "resolved" && (
                    <button
                      onClick={() => resolve(alert.id)}
                      className="text-xs px-3 py-1.5 bg-green-700 hover:bg-green-600 rounded text-white font-medium transition"
                    >
                      Resolve
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
          {filteredAlerts.length === 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded p-8 text-center text-gray-500 text-sm">
              No alerts match your active filters.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
