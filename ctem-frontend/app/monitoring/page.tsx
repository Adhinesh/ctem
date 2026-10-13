"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { SecurityEvent, UebaEvent, Asset } from "@/lib/types";
import { Badge } from "@/components/Badge";

export default function MonitoringPage() {
  const [activeTab, setActiveTab] = useState<"logs" | "ueba" | "drift">("logs");

  // Assets list for dropdowns
  const [assets, setAssets] = useState<Asset[]>([]);

  // Security Events State
  const [secEvents, setSecEvents] = useState<SecurityEvent[]>([]);
  const [secLoading, setSecLoading] = useState(true);
  const [secSource, setSecSource] = useState("suricata");
  const [secSeverity, setSecSeverity] = useState<"low" | "medium" | "high" | "critical">("high");
  const [secEventType, setSecEventType] = useState("nids_exploit_attempt");
  const [secAssetId, setSecAssetId] = useState("");
  const [secSummary, setSecSummary] = useState("");
  const [secSubmitting, setSecSubmitting] = useState(false);
  const [secFeedback, setSecFeedback] = useState<string | null>(null);

  // UEBA State
  const [uebaEvents, setUebaEvents] = useState<UebaEvent[]>([]);
  const [uebaLoading, setUebaLoading] = useState(true);
  const [uebaUsername, setUebaUsername] = useState("admin@corp.internal");
  const [uebaEventType, setUebaEventType] = useState("failed_login");
  const [uebaSourceIp, setUebaSourceIp] = useState("198.51.100.45");
  const [uebaSubmitting, setUebaSubmitting] = useState(false);
  const [uebaFeedback, setUebaFeedback] = useState<string | null>(null);

  useEffect(() => {
    loadAssets();
    loadSecEvents();
    loadUebaEvents();
  }, []);

  async function loadAssets() {
    try {
      const res = await api.listAssets();
      setAssets(res.assets || []);
    } catch (err) {
      console.error(err);
    }
  }

  async function loadSecEvents() {
    setSecLoading(true);
    try {
      const res = await api.listSecurityEvents();
      setSecEvents(res.events || []);
    } catch (err) {
      console.error(err);
    } finally {
      setSecLoading(false);
    }
  }

  async function loadUebaEvents() {
    setUebaLoading(true);
    try {
      const res = await api.listUebaEvents();
      setUebaEvents(res.events || []);
    } catch (err) {
      console.error(err);
    } finally {
      setUebaLoading(false);
    }
  }

  async function submitSecurityEvent(e: React.FormEvent) {
    e.preventDefault();
    setSecSubmitting(true);
    setSecFeedback(null);
    try {
      await api.ingestSecurityEvent({
        source: secSource,
        severity: secSeverity,
        event_type: secEventType,
        asset_id: secAssetId || null,
        summary: secSummary || `${secSource.toUpperCase()} detected ${secEventType}`,
      });
      setSecFeedback("Event ingested successfully! High and critical events trigger security alerts.");
      setSecSummary("");
      await loadSecEvents();
      setTimeout(() => setSecFeedback(null), 5000);
    } catch (err) {
      setSecFeedback("Failed to ingest security event: " + String(err));
    } finally {
      setSecSubmitting(false);
    }
  }

  async function submitUebaEvent(e: React.FormEvent) {
    e.preventDefault();
    if (!uebaUsername.trim()) return;
    setUebaSubmitting(true);
    setUebaFeedback(null);
    try {
      await api.recordUebaEvent({
        username: uebaUsername.trim(),
        event_type: uebaEventType,
        source_ip: uebaSourceIp.trim() || null,
      });
      setUebaFeedback("UEBA event recorded! Evaluated against anomaly baseline rules.");
      await loadUebaEvents();
      setTimeout(() => setUebaFeedback(null), 5000);
    } catch (err) {
      setUebaFeedback("Failed to record UEBA event: " + String(err));
    } finally {
      setUebaSubmitting(false);
    }
  }

  async function simulateBruteForce() {
    setUebaSubmitting(true);
    setUebaFeedback("Simulating 5 rapid failed logins to trigger brute force anomaly alert...");
    try {
      const user = "victim_admin@corp.internal";
      for (let i = 0; i < 5; i++) {
        await api.recordUebaEvent({
          username: user,
          event_type: "failed_login",
          source_ip: "203.0.113." + (10 + i),
        });
      }
      setUebaFeedback("Success! 5 failed logins recorded. Check Alerts tab for the new High Severity UEBA alert.");
      await loadUebaEvents();
      setTimeout(() => setUebaFeedback(null), 6000);
    } catch (err) {
      setUebaFeedback("Simulation failed: " + String(err));
    } finally {
      setUebaSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Security Monitoring & Identity Analytics</h1>
        <p className="text-sm text-gray-400">
          Team 4 ingestion pipelines: Security Onion logs, UEBA identity anomaly detection, and port drift tracking
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800 gap-6">
        <button
          onClick={() => setActiveTab("logs")}
          className={`pb-3 text-sm font-medium border-b-2 transition ${
            activeTab === "logs"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          Security Onion Logs ({secEvents.length})
        </button>
        <button
          onClick={() => setActiveTab("ueba")}
          className={`pb-3 text-sm font-medium border-b-2 transition ${
            activeTab === "ueba"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          UEBA Identity Analytics ({uebaEvents.length})
        </button>
        <button
          onClick={() => setActiveTab("drift")}
          className={`pb-3 text-sm font-medium border-b-2 transition ${
            activeTab === "drift"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          Exposure & Drift Engine
        </button>
      </div>

      {/* TAB 1: SECURITY ONION LOGS */}
      {activeTab === "logs" && (
        <div className="space-y-6">
          {secFeedback && (
            <div className="p-3 rounded text-sm bg-blue-950/40 border border-blue-800 text-blue-300">
              {secFeedback}
            </div>
          )}

          {/* Ingestion Box */}
          <form onSubmit={submitSecurityEvent} className="bg-gray-900 border border-gray-800 rounded p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-200">Ingest Security Onion / SIEM Event</h2>
              <span className="text-xs text-gray-500">API: POST /logs/events</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Source</label>
                <select
                  value={secSource}
                  onChange={(e) => setSecSource(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
                >
                  <option value="suricata">Suricata (NIDS)</option>
                  <option value="zeek">Zeek (NSM)</option>
                  <option value="wazuh">Wazuh (HIDS / EDR)</option>
                  <option value="ossec">OSSEC</option>
                  <option value="syslog">Syslog</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Severity</label>
                <select
                  value={secSeverity}
                  onChange={(e) => setSecSeverity(e.target.value as any)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-medium"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Event Type</label>
                <input
                  required
                  value={secEventType}
                  onChange={(e) => setSecEventType(e.target.value)}
                  placeholder="e.g. nids_exploit_attempt"
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Associated Asset (Optional)</label>
                <select
                  value={secAssetId}
                  onChange={(e) => setSecAssetId(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
                >
                  <option value="">None / Unassigned</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname || a.ip_address} ({a.zone || "external"})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="mt-3">
              <label className="text-xs text-gray-400 block mb-1">Event Summary / Signature Details</label>
              <input
                value={secSummary}
                onChange={(e) => setSecSummary(e.target.value)}
                placeholder="e.g. ET EXPLOIT Apache Log4j RCE Attempt Detected against TCP:8080"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              />
            </div>

            <div className="mt-4 pt-3 border-t border-gray-800 flex justify-end">
              <button
                type="submit"
                disabled={secSubmitting}
                className="px-4 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50"
              >
                {secSubmitting ? "Ingesting..." : "Ingest Event"}
              </button>
            </div>
          </form>

          {/* Events Table */}
          <div>
            <h2 className="text-lg font-semibold mb-3">Security Onion Feed</h2>
            {secLoading ? (
              <p className="text-gray-400 text-sm">Loading security events...</p>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800 text-gray-400 text-left">
                    <tr>
                      <th className="px-4 py-2.5">Time</th>
                      <th className="px-4 py-2.5">Source</th>
                      <th className="px-4 py-2.5">Severity</th>
                      <th className="px-4 py-2.5">Event Type</th>
                      <th className="px-4 py-2.5">Summary</th>
                      <th className="px-4 py-2.5">Asset</th>
                    </tr>
                  </thead>
                  <tbody>
                    {secEvents.map((evt) => {
                      const linkedAsset = assets.find((a) => a.id === evt.asset_id);
                      return (
                        <tr key={evt.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                          <td className="px-4 py-2.5 text-xs text-gray-400 whitespace-nowrap">
                            {new Date(evt.occurred_at || evt.created_at || "").toLocaleTimeString()}
                          </td>
                          <td className="px-4 py-2.5 font-mono text-xs uppercase text-blue-400">
                            {evt.source}
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge value={evt.severity} />
                          </td>
                          <td className="px-4 py-2.5 font-mono text-xs text-gray-300">{evt.event_type}</td>
                          <td className="px-4 py-2.5 text-gray-200">{evt.summary || "-"}</td>
                          <td className="px-4 py-2.5 text-xs">
                            {linkedAsset ? (
                              <Link href={`/assets/${linkedAsset.id}`} className="text-blue-400 hover:underline">
                                {linkedAsset.hostname || linkedAsset.ip_address}
                              </Link>
                            ) : (
                              <span className="text-gray-500">-</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {secEvents.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                          No security events ingested yet. Ingest an event above to test.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: UEBA ANALYTICS */}
      {activeTab === "ueba" && (
        <div className="space-y-6">
          {uebaFeedback && (
            <div className="p-3 rounded text-sm bg-blue-950/40 border border-blue-800 text-blue-300">
              {uebaFeedback}
            </div>
          )}

          {/* Anomaly Engine Rules Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <span className="text-xs font-mono bg-red-950/60 text-red-300 px-2 py-0.5 rounded border border-red-800">
                Rule 1: Failed Login Burst
              </span>
              <p className="text-sm font-semibold text-white mt-2">Brute Force Detection</p>
              <p className="text-xs text-gray-400 mt-1">
                ≥ 5 failed logins within 15 minutes automatically raises a <strong>High Severity Alert</strong>.
              </p>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <span className="text-xs font-mono bg-orange-950/60 text-orange-300 px-2 py-0.5 rounded border border-orange-800">
                Rule 2: New Source IP
              </span>
              <p className="text-sm font-semibold text-white mt-2">Geographic / Origin Drift</p>
              <p className="text-xs text-gray-400 mt-1">
                First observed successful login from an unknown IP raises a <strong>Medium Severity Alert</strong>.
              </p>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <span className="text-xs font-mono bg-yellow-950/60 text-yellow-300 px-2 py-0.5 rounded border border-yellow-800">
                Rule 3: Off-Hours Activity
              </span>
              <p className="text-sm font-semibold text-white mt-2">Temporal Anomaly</p>
              <p className="text-xs text-gray-400 mt-1">
                Logins between 22:00 and 06:00 UTC generate a <strong>Low Severity Notice</strong> for review.
              </p>
            </div>
          </div>

          {/* UEBA Simulator Box */}
          <div className="bg-gray-900 border border-gray-800 rounded p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-200">Record UEBA Identity Event</h2>
              <button
                type="button"
                onClick={simulateBruteForce}
                disabled={uebaSubmitting}
                className="text-xs px-3 py-1 bg-red-950/50 border border-red-800 hover:bg-red-900/60 text-red-300 rounded font-medium disabled:opacity-50"
              >
                ⚡ Quick Test: Simulate 5x Brute-Force Burst
              </button>
            </div>

            <form onSubmit={submitUebaEvent} className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Username / User Principal</label>
                <input
                  required
                  value={uebaUsername}
                  onChange={(e) => setUebaUsername(e.target.value)}
                  placeholder="e.g. jdoe@corp.internal"
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Event Type</label>
                <select
                  value={uebaEventType}
                  onChange={(e) => setUebaEventType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
                >
                  <option value="login">login (Successful)</option>
                  <option value="failed_login">failed_login (Authentication Failure)</option>
                  <option value="privilege_escalation">privilege_escalation</option>
                  <option value="password_reset">password_reset</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Source IP Address</label>
                <input
                  value={uebaSourceIp}
                  onChange={(e) => setUebaSourceIp(e.target.value)}
                  placeholder="e.g. 198.51.100.45"
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono"
                />
              </div>

              <div className="md:col-span-3 flex justify-end mt-2">
                <button
                  type="submit"
                  disabled={uebaSubmitting}
                  className="px-4 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50"
                >
                  {uebaSubmitting ? "Recording..." : "Record Behavior Event"}
                </button>
              </div>
            </form>
          </div>

          {/* UEBA Feed Table */}
          <div>
            <h2 className="text-lg font-semibold mb-3">User Behavior Events Log</h2>
            {uebaLoading ? (
              <p className="text-gray-400 text-sm">Loading UEBA logs...</p>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800 text-gray-400 text-left">
                    <tr>
                      <th className="px-4 py-2.5">Time</th>
                      <th className="px-4 py-2.5">Username</th>
                      <th className="px-4 py-2.5">Event Type</th>
                      <th className="px-4 py-2.5">Source IP</th>
                      <th className="px-4 py-2.5">Anomaly Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {uebaEvents.map((evt) => (
                      <tr key={evt.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                        <td className="px-4 py-2.5 text-xs text-gray-400 whitespace-nowrap">
                          {new Date(evt.occurred_at || evt.created_at || "").toLocaleString()}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-sm text-blue-300">{evt.username}</td>
                        <td className="px-4 py-2.5">
                          <Badge
                            value={
                              evt.event_type === "failed_login"
                                ? "high"
                                : evt.event_type === "login"
                                ? "resolved"
                                : "medium"
                            }
                          />{" "}
                          <span className="text-xs font-mono ml-1 text-gray-400">{evt.event_type}</span>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{evt.source_ip || "-"}</td>
                        <td className="px-4 py-2.5 text-xs text-gray-400">Evaluated against rules</td>
                      </tr>
                    ))}
                    {uebaEvents.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                          No UEBA events recorded yet. Run a simulation above to test.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: EXPOSURE & DRIFT ENGINE */}
      {activeTab === "drift" && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded p-6">
            <h2 className="text-lg font-semibold text-white mb-2">Automated Attack Surface Drift Detection</h2>
            <p className="text-sm text-gray-400 mb-6 leading-relaxed">
              Whenever a recurring or on-demand scan completes, the CTEM Change Detection service compares the newly
              discovered open ports against the historical baseline for each asset. Any newly opened port immediately triggers
              an <code className="text-yellow-400 bg-gray-800 px-1.5 py-0.5 rounded">asset_change</code> alert with Medium severity.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-gray-800/50 border border-gray-700/60 rounded p-4">
                <div className="w-8 h-8 rounded bg-blue-900/60 text-blue-400 flex items-center justify-center font-bold mb-2">
                  1
                </div>
                <h3 className="font-semibold text-sm text-gray-200">Recon Scan Ingestion</h3>
                <p className="text-xs text-gray-400 mt-1">
                  Active Nmap scan discovers live ports and services on targets and subdomains.
                </p>
              </div>

              <div className="bg-gray-800/50 border border-gray-700/60 rounded p-4">
                <div className="w-8 h-8 rounded bg-yellow-900/60 text-yellow-400 flex items-center justify-center font-bold mb-2">
                  2
                </div>
                <h3 className="font-semibold text-sm text-gray-200">State Diff Computation</h3>
                <p className="text-xs text-gray-400 mt-1">
                  Delta engine computes: <code className="text-xs text-blue-300">new_ports = current_ports - baseline_ports</code>.
                </p>
              </div>

              <div className="bg-gray-800/50 border border-gray-700/60 rounded p-4">
                <div className="w-8 h-8 rounded bg-red-900/60 text-red-400 flex items-center justify-center font-bold mb-2">
                  3
                </div>
                <h3 className="font-semibold text-sm text-gray-200">Automated Exposure Alert</h3>
                <p className="text-xs text-gray-400 mt-1">
                  Dispatches alert titled <em>&quot;New open port(s) detected: [...]&quot;</em> directly to the Alerts triage queue.
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <Link
                href="/alerts"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm text-white font-medium inline-block"
              >
                View Drift Alerts in Alerts Queue →
              </Link>
              <Link
                href="/scans"
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300 font-medium inline-block"
              >
                Launch New Scan →
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
