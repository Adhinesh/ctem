"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Peripheral } from "@/lib/types";
import { Badge } from "@/components/Badge";

const DEVICE_TYPES = ["router", "hard_drive", "pendrive", "usb_storage", "other"];

export default function PeripheralsPage() {
  const [peripherals, setPeripherals] = useState<Peripheral[]>([]);
  const [loading, setLoading] = useState(true);

  // Registration Form State
  const [deviceType, setDeviceType] = useState("pendrive");
  const [serialNumber, setSerialNumber] = useState("");
  const [label, setLabel] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [authorized, setAuthorized] = useState(true);
  const [registering, setRegistering] = useState(false);

  // Check State
  const [checkSerial, setCheckSerial] = useState("");
  const [checkResult, setCheckResult] = useState<any>(null);
  const [checking, setChecking] = useState(false);

  // Toast / notification
  const [reachabilityMsg, setReachabilityMsg] = useState<{ id: string; text: string; success: boolean } | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const result = await api.listPeripherals();
      setPeripherals(result.peripherals || []);
    } catch (err) {
      console.error("Failed to load peripherals:", err);
    } finally {
      setLoading(false);
    }
  }

  async function register(e: React.FormEvent) {
    e.preventDefault();
    if (!serialNumber.trim()) return;
    setRegistering(true);
    try {
      await api.registerPeripheral({
        device_type: deviceType,
        serial_number: serialNumber.trim(),
        label: label.trim() || null,
        ip_address: ipAddress.trim() || null,
        authorized,
        authorized_by: authorized ? "dashboard_admin" : null,
      });
      setSerialNumber("");
      setLabel("");
      setIpAddress("");
      load();
    } catch (err) {
      alert("Failed to register peripheral");
    } finally {
      setRegistering(false);
    }
  }

  async function toggleAuthorization(peripheral: Peripheral) {
    try {
      await api.authorizePeripheral(peripheral.id, !peripheral.authorized, "dashboard_admin");
      load();
    } catch (err) {
      alert("Failed to update authorization");
    }
  }

  async function deleteDevice(peripheral: Peripheral) {
    if (!confirm(`Are you sure you want to remove device "${peripheral.label || peripheral.serial_number}"?`)) return;
    try {
      await api.deletePeripheral(peripheral.id);
      load();
    } catch (err) {
      alert("Failed to delete peripheral");
    }
  }

  async function checkReachability(peripheral: Peripheral) {
    try {
      const result = await api.checkPeripheralReachability(peripheral.id);
      const isOnline = result.result === "reachable" || result.result === "online";
      setReachabilityMsg({
        id: peripheral.id,
        text: `Ping check result for ${peripheral.label || peripheral.ip_address}: ${result.result}`,
        success: isOnline,
      });
      setTimeout(() => setReachabilityMsg(null), 5000);
    } catch (err) {
      setReachabilityMsg({
        id: peripheral.id,
        text: `Reachability check failed: ${String(err)}`,
        success: false,
      });
    }
  }

  async function runCheck() {
    if (!checkSerial.trim()) return;
    setChecking(true);
    try {
      const result = await api.checkPeripheral(checkSerial.trim());
      setCheckResult(result);
    } catch (err) {
      setCheckResult({ result: "error", message: "Failed to verify serial" });
    } finally {
      setChecking(false);
    }
  }

  const authorizedCount = peripherals.filter((p) => p.authorized).length;
  const unauthorizedCount = peripherals.filter((p) => !p.authorized).length;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Peripheral Allowlist & Hardware Control</h1>
        <p className="text-sm text-gray-400">
          Manage hardware peripheral authorization, router reachability, and unauthorized connection alerts
        </p>
      </div>

      {reachabilityMsg && (
        <div
          className={`p-3 rounded text-sm border flex items-center justify-between ${
            reachabilityMsg.success
              ? "bg-green-950/40 border-green-800 text-green-300"
              : "bg-red-950/40 border-red-800 text-red-300"
          }`}
        >
          <span>{reachabilityMsg.text}</span>
          <button onClick={() => setReachabilityMsg(null)} className="text-xs font-bold px-2">
            ✕
          </button>
        </div>
      )}

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded p-4">
          <p className="text-xs text-gray-400 uppercase tracking-wider font-semibold">Total Devices</p>
          <p className="text-2xl font-bold mt-1 text-white">{peripherals.length}</p>
        </div>
        <div className="bg-gray-900 border border-green-900/40 rounded p-4">
          <p className="text-xs text-green-400 uppercase tracking-wider font-semibold">Authorized</p>
          <p className="text-2xl font-bold mt-1 text-green-400">{authorizedCount}</p>
        </div>
        <div className="bg-gray-900 border border-red-900/40 rounded p-4">
          <p className="text-xs text-red-400 uppercase tracking-wider font-semibold">Unauthorized / Blocked</p>
          <p className="text-2xl font-bold mt-1 text-red-400">{unauthorizedCount}</p>
        </div>
      </div>

      {/* Grid: Check Tool & Registration Form */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Hardware Query Checker */}
        <div className="bg-gray-900 border border-gray-800 rounded p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-200 mb-1">Lookup Hardware Authorization</h2>
            <p className="text-xs text-gray-400 mb-4">
              Query USB serial or device identifier to verify authorization status. Unauthorized checks trigger security alerts.
            </p>
            <div className="flex gap-2">
              <input
                value={checkSerial}
                onChange={(e) => setCheckSerial(e.target.value)}
                placeholder="Enter Serial Number or HW ID..."
                className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm flex-1 font-mono focus:border-blue-500 focus:outline-none"
              />
              <button
                onClick={runCheck}
                disabled={checking}
                className="px-4 py-2 text-sm rounded bg-blue-600 text-white font-medium hover:bg-blue-500 disabled:opacity-50"
              >
                {checking ? "Checking..." : "Verify"}
              </button>
            </div>
          </div>

          {checkResult && (
            <div
              className={`mt-4 p-3.5 rounded border ${
                checkResult.result === "authorized"
                  ? "bg-green-950/30 border-green-800 text-green-300"
                  : "bg-red-950/30 border-red-800 text-red-300"
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <Badge value={checkResult.result === "authorized" ? "resolved" : "critical"} />
                <span className="font-semibold uppercase text-xs">{checkResult.result}</span>
              </div>
              <p className="text-xs text-gray-300">
                {checkResult.result === "authorized"
                  ? "Device is present in the enterprise allowlist and approved for use."
                  : "Device is NOT approved or not recognized. An unauthorized peripheral alert has been logged."}
              </p>
            </div>
          )}
        </div>

        {/* Register Device */}
        <form onSubmit={register} className="bg-gray-900 border border-gray-800 rounded p-5">
          <h2 className="text-sm font-semibold text-gray-200 mb-1">Register Device to Allowlist</h2>
          <p className="text-xs text-gray-400 mb-4">Add authorized network or storage peripherals</p>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Device Type</label>
              <select
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              >
                {DEVICE_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type.replace("_", " ").toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Serial / Identifier *</label>
              <input
                required
                value={serialNumber}
                onChange={(e) => setSerialNumber(e.target.value)}
                placeholder="e.g. SN-8849201"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Label / Owner</label>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. SecOps Router A"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">IP Address (Routers)</label>
              <input
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                placeholder="e.g. 192.168.1.1"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono"
              />
            </div>
          </div>

          <div className="flex items-center justify-between mt-4 pt-2 border-t border-gray-800">
            <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="rounded bg-gray-800 border-gray-700"
              />
              <span>Set as Authorized</span>
            </label>
            <button
              type="submit"
              disabled={registering}
              className="px-4 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50"
            >
              {registering ? "Registering..." : "Add to Allowlist"}
            </button>
          </div>
        </form>
      </div>

      {/* Devices List */}
      <div>
        <h2 className="text-lg font-semibold mb-3">Registered Hardware Peripherals</h2>
        {loading ? (
          <p className="text-gray-400">Loading devices...</p>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-800 text-gray-400 text-left">
                <tr>
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">Serial / Identifier</th>
                  <th className="px-4 py-2.5">Label</th>
                  <th className="px-4 py-2.5">IP Address</th>
                  <th className="px-4 py-2.5">Authorization</th>
                  <th className="px-4 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {peripherals.map((peripheral) => (
                  <tr key={peripheral.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                    <td className="px-4 py-2.5 font-mono text-gray-300 uppercase text-xs">
                      {peripheral.device_type}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-blue-400">
                      {peripheral.serial_number || peripheral.device_identifier || "-"}
                    </td>
                    <td className="px-4 py-2.5 text-gray-300">{peripheral.label || "-"}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400">
                      {peripheral.ip_address || "-"}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge value={peripheral.authorized ? "resolved" : "critical"} />
                    </td>
                    <td className="px-4 py-2.5 text-right space-x-3">
                      <button
                        onClick={() => toggleAuthorization(peripheral)}
                        className="text-xs text-blue-400 hover:underline font-medium"
                      >
                        {peripheral.authorized ? "Revoke" : "Authorize"}
                      </button>
                      {peripheral.ip_address && (
                        <button
                          onClick={() => checkReachability(peripheral)}
                          className="text-xs text-purple-400 hover:underline font-medium"
                        >
                          Ping Check
                        </button>
                      )}
                      <button
                        onClick={() => deleteDevice(peripheral)}
                        className="text-xs text-red-400 hover:underline font-medium"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {peripherals.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                      No hardware peripherals registered in allowlist.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
