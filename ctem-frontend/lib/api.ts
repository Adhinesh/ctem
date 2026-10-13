function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    const envUrl = process.env.NEXT_PUBLIC_API_BASE_URL;
    if (envUrl) {
      try {
        const parsed = new URL(envUrl);
        // If configured as localhost but browser accessed via LAN/remote IP (e.g. 10.255.255.254)
        if (
          (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") &&
          window.location.hostname !== "localhost" &&
          window.location.hostname !== "127.0.0.1"
        ) {
          return `${window.location.protocol}//${window.location.hostname}:8000`;
        }
        return envUrl;
      } catch {
        return envUrl;
      }
    }
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
}

async function request(path: string, options: RequestInit = {}) {
  const baseUrl = getBaseUrl();
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      cache: "no-store",
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`${response.status} ${response.statusText}: ${body}`);
    }

    if (response.status === 204) {
      return null;
    }

    return await response.json();
  } catch (err: any) {
    if (err?.name === "TypeError" && (err?.message?.includes("fetch") || err?.message?.includes("NetworkError"))) {
      console.warn(`[CTEM API] Network connectivity issue connecting to ${baseUrl}${path}. Ensure FastAPI backend is running.`);
    }
    throw err;
  }
}

export const api = {
  createScan(target: string, targetType: string, labels: Record<string, any> | null, tenantId?: string, forceNew = false) {
    const headers: Record<string, string> = {};
    if (tenantId) headers["X-Tenant-Id"] = tenantId;
    return request("/scans", {
      method: "POST",
      headers,
      body: JSON.stringify({ target, target_type: targetType, labels, force_new: forceNew }),
    });
  },
  getScan(scanId: string) {
    return request(`/scans/${scanId}`);
  },
  getScanAssets(scanId: string) {
    return request(`/scans/${scanId}/assets`);
  },
  cancelScan(scanId: string) {
    return request(`/scans/${scanId}/cancel`, { method: "POST" });
  },
  rescan(scanId: string) {
    return request(`/scans/${scanId}/rescan`, { method: "POST" });
  },
  deleteScan(scanId: string) {
    return request(`/scans/${scanId}`, { method: "DELETE" });
  },
  getScanHistory(target?: string, tenantId?: string) {
    const query = target ? `?target=${encodeURIComponent(target)}` : "";
    const headers: Record<string, string> = {};
    if (tenantId) headers["X-Tenant-Id"] = tenantId;
    return request(`/scans${query}`, { headers });
  },

  listAssets(filters: { asset_status?: string; zone?: string; q?: string } = {}) {
    const params = new URLSearchParams(filters as Record<string, string>).toString();
    return request(`/assets${params ? `?${params}` : ""}`);
  },
  getAsset(assetId: string) {
    return request(`/assets/${assetId}`);
  },
  confirmAsset(assetId: string) {
    return request(`/assets/${assetId}/confirm`, { method: "POST" });
  },
  editAsset(assetId: string, fields: Record<string, any>) {
    return request(`/assets/${assetId}`, { method: "PATCH", body: JSON.stringify(fields) });
  },
  deleteAsset(assetId: string) {
    return request(`/assets/${assetId}`, { method: "DELETE" });
  },
  getAssetChanges(assetId: string) {
    return request(`/assets/${assetId}/changes`);
  },
  declareAssets(declaredBy: string, assets: any[]) {
    return request("/assets/declared", {
      method: "POST",
      body: JSON.stringify({ declared_by: declaredBy, assets }),
    });
  },

  getHeatmap() {
    return request("/risk/heatmap");
  },
  rescoreRisk() {
    return request("/risk/rescore", { method: "POST" });
  },
  listRiskScores(filters: { priority_tier?: string; min_score?: number } = {}) {
    const params = new URLSearchParams(filters as any).toString();
    return request(`/risk/scores${params ? `?${params}` : ""}`);
  },
  getAssetRisk(assetId: string) {
    return request(`/risk/scores/${assetId}`);
  },
  explainAssetRisk(assetId: string) {
    return request(`/risk/scores/${assetId}/explain`);
  },

  listAlerts(filters: { status?: string; severity?: string; alert_type?: string; asset_id?: string } = {}) {
    const params = new URLSearchParams(filters as Record<string, string>).toString();
    return request(`/alerts${params ? `?${params}` : ""}`);
  },
  acknowledgeAlert(alertId: string) {
    return request(`/alerts/${alertId}/acknowledge`, { method: "POST" });
  },
  resolveAlert(alertId: string) {
    return request(`/alerts/${alertId}/resolve`, { method: "POST" });
  },

  listPeripherals(filters: { authorized?: boolean; device_type?: string } = {}) {
    const params = new URLSearchParams(filters as any).toString();
    return request(`/peripherals${params ? `?${params}` : ""}`);
  },
  registerPeripheral(payload: Record<string, any>) {
    return request("/peripherals", { method: "POST", body: JSON.stringify(payload) });
  },
  deletePeripheral(peripheralId: string) {
    return request(`/peripherals/${peripheralId}`, { method: "DELETE" });
  },
  authorizePeripheral(peripheralId: string, authorized: boolean, authorizedBy: string) {
    return request(`/peripherals/${peripheralId}/authorize`, {
      method: "POST",
      body: JSON.stringify({ authorized, authorized_by: authorizedBy }),
    });
  },
  checkPeripheral(serialNumber?: string, deviceIdentifier?: string) {
    return request("/peripherals/check", {
      method: "POST",
      body: JSON.stringify({ serial_number: serialNumber, device_identifier: deviceIdentifier }),
    });
  },
  checkPeripheralReachability(peripheralId: string) {
    return request(`/peripherals/${peripheralId}/check-reachability`, { method: "POST" });
  },

  listSecurityEvents(filters: { asset_id?: string; severity?: string } = {}) {
    const params = new URLSearchParams(filters as Record<string, string>).toString();
    return request(`/logs/events${params ? `?${params}` : ""}`);
  },
  ingestSecurityEvent(payload: { source: string; asset_id?: string | null; event_type: string; severity: string; summary?: string | null; occurred_at?: string }) {
    return request("/logs/events", { method: "POST", body: JSON.stringify(payload) });
  },

  listUebaEvents(filters: { username?: string; event_type?: string } = {}) {
    const params = new URLSearchParams(filters as Record<string, string>).toString();
    return request(`/ueba/events${params ? `?${params}` : ""}`);
  },
  recordUebaEvent(payload: { username: string; event_type: string; source_ip?: string | null; occurred_at?: string }) {
    return request("/ueba/events", { method: "POST", body: JSON.stringify(payload) });
  },

  getBlastRadiusOverview(mode?: string) {
    const params = mode ? `?mode=${encodeURIComponent(mode)}` : "";
    return request(`/risk/blast-radius${params}`);
  },
  getAssetBlastRadius(assetId: string, mode?: string, depth = 2) {
    const query = new URLSearchParams();
    if (mode) query.set("mode", mode);
    if (depth) query.set("depth", depth.toString());
    const qStr = query.toString();
    return request(`/risk/blast-radius/${assetId}${qStr ? `?${qStr}` : ""}`);
  },
  simulateBlastRadius(assetId: string, payload: { isolate_subnet?: boolean; sever_dependencies?: boolean; isolate_zone?: boolean; mode?: string }) {
    return request(`/risk/blast-radius/${assetId}/simulate`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
  listDependencies(assetId?: string) {
    const params = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
    return request(`/risk/dependencies${params}`);
  },
  createDependency(assetId: string, dependsOnAssetId: string) {
    return request("/risk/dependencies", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, depends_on_asset_id: dependsOnAssetId }),
    });
  },
  deleteDependency(dependencyId: string) {
    return request(`/risk/dependencies/${dependencyId}`, { method: "DELETE" });
  },
};

