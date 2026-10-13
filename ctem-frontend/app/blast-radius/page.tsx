"use client";

import React, { useEffect, useState, useMemo, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import {
  Asset,
  BlastRadiusDetail,
  BlastRadiusOverview,
  AssetDependency,
  BlastRadiusSimulation,
} from "@/lib/types";
import { Badge } from "@/components/Badge";
import { BlastRadiusGraph } from "@/components/BlastRadiusGraph";
import { DeclareDependencyModal } from "@/components/DeclareDependencyModal";

function BlastRadiusContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const initialAssetId = searchParams.get("assetId");

  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [mode, setMode] = useState<"combined" | "same_subnet" | "same_zone" | "dependency_edges">("combined");
  
  const [overview, setOverview] = useState<BlastRadiusOverview | null>(null);
  const [blastDetail, setBlastDetail] = useState<BlastRadiusDetail | null>(null);
  const [dependencies, setDependencies] = useState<AssetDependency[]>([]);
  
  // Simulation Sandbox State
  const [isolateSubnet, setIsolateSubnet] = useState(false);
  const [severDependencies, setSeverDependencies] = useState(false);
  const [isolateZone, setIsolateZone] = useState(false);
  const [simulationResult, setSimulationResult] = useState<BlastRadiusSimulation | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  // Modals & UI State
  const [isDepModalOpen, setIsDepModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [assetSearchQuery, setAssetSearchQuery] = useState("");

  // Load assets and initial overview
  useEffect(() => {
    loadInitialData();
  }, []);

  // When selectedAssetId or mode or containment flags change, reload blast radius detail
  useEffect(() => {
    if (selectedAssetId) {
      loadAssetBlastRadius(selectedAssetId, mode);
    }
  }, [selectedAssetId, mode]);

  // When containment toggles change, run live simulation
  useEffect(() => {
    if (selectedAssetId && (isolateSubnet || severDependencies || isolateZone)) {
      runSimulation();
    } else {
      setSimulationResult(null);
    }
  }, [isolateSubnet, severDependencies, isolateZone]);

  async function loadInitialData() {
    setLoading(true);
    try {
      const [assetsRes, overviewRes, depsRes] = await Promise.all([
        api.listAssets(),
        api.getBlastRadiusOverview("combined"),
        api.listDependencies(),
      ]);

      const assetList = assetsRes?.assets || [];
      setAssets(assetList);
      setOverview(overviewRes);
      setDependencies(depsRes?.dependencies || []);

      // If URL had ?assetId, use it; otherwise default to highest risk asset or first asset
      if (initialAssetId && assetList.some((a: Asset) => a.id === initialAssetId)) {
        setSelectedAssetId(initialAssetId);
      } else if (overviewRes?.ranked_assets?.length > 0) {
        setSelectedAssetId(overviewRes.ranked_assets[0].asset_id);
      } else if (assetList.length > 0) {
        setSelectedAssetId(assetList[0].id);
      }
    } catch (err) {
      console.error("Failed to load blast radius data:", err);
    } finally {
      setLoading(false);
    }
  }

  async function loadAssetBlastRadius(assetId: string, currentMode: string) {
    setRefreshing(true);
    try {
      const detail = await api.getAssetBlastRadius(assetId, currentMode, 2);
      setBlastDetail(detail);
      // Reset simulation toggles when switching primary asset
      setIsolateSubnet(false);
      setSeverDependencies(false);
      setIsolateZone(false);
      setSimulationResult(null);
    } catch (err) {
      console.error("Failed to load asset blast radius:", err);
    } finally {
      setRefreshing(false);
    }
  }

  async function runSimulation() {
    if (!selectedAssetId) return;
    setIsSimulating(true);
    try {
      const sim = await api.simulateBlastRadius(selectedAssetId, {
        isolate_subnet: isolateSubnet,
        sever_dependencies: severDependencies,
        isolate_zone: isolateZone,
        mode,
      });
      setSimulationResult(sim);
    } catch (err) {
      console.error("Simulation failed:", err);
    } finally {
      setIsSimulating(false);
    }
  }

  async function handleDeleteDependency(depId: string) {
    if (!confirm("Are you sure you want to remove this service dependency link?")) return;
    try {
      await api.deleteDependency(depId);
      const [depsRes, overviewRes] = await Promise.all([
        api.listDependencies(),
        api.getBlastRadiusOverview(mode),
      ]);
      setDependencies(depsRes?.dependencies || []);
      setOverview(overviewRes);
      if (selectedAssetId) {
        loadAssetBlastRadius(selectedAssetId, mode);
      }
    } catch (err) {
      alert("Failed to delete dependency: " + err);
    }
  }

  const filteredAssets = useMemo(() => {
    if (!assetSearchQuery) return assets;
    const q = assetSearchQuery.toLowerCase();
    return assets.filter(
      (a) =>
        a.hostname?.toLowerCase().includes(q) ||
        a.ip_address?.toLowerCase().includes(q) ||
        a.asset_type?.toLowerCase().includes(q) ||
        a.zone?.toLowerCase().includes(q)
    );
  }, [assets, assetSearchQuery]);

  // Display detail: if simulation result is active, use simulated blast radius
  const activeDetail = simulationResult?.simulated_blast_radius || blastDetail;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-gray-400 text-sm">Evaluating network topology & blast radius...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-300 pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">💥</span>
            <h1 className="text-2xl font-bold tracking-tight text-gray-100">Blast Radius & Lateral Reachability</h1>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Simulate and visualize collateral damage, attack reachability, and lateral movement vectors across subnets, zones, and service dependencies.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsDepModalOpen(true)}
            className="px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5"
          >
            <span>🔗</span> + Declare Dependency
          </button>
          <button
            onClick={() => loadInitialData()}
            className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5"
          >
            <span>🔄</span> Refresh Topology
          </button>
        </div>
      </div>

      {/* Executive KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500 font-semibold">Peak Blast Multiplier</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold text-red-400">
              {overview?.highest_blast_radius ? `${overview.highest_blast_radius}x` : "1.0x"}
            </span>
            <span className="text-xs text-gray-400">max scaling</span>
          </div>
          <p className="text-xs text-gray-500 mt-1">Magnifies vulnerability CVSS/EPSS composite risk</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500 font-semibold">Critical Assets at Risk</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold text-amber-400">
              {overview?.assets_with_critical_exposure ?? 0}
            </span>
            <span className="text-xs text-gray-400">exposed systems</span>
          </div>
          <p className="text-xs text-gray-500 mt-1">Can reach at least one Critical crown-jewel asset</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500 font-semibold">Org Average Radius</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold text-blue-400">
              {overview?.avg_blast_radius ? `${overview.avg_blast_radius}x` : "1.0x"}
            </span>
            <span className="text-xs text-gray-400">across {overview?.total_assets || 0} assets</span>
          </div>
          <p className="text-xs text-gray-500 mt-1">Average lateral movement propagation index</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500 font-semibold">Declared Dependencies</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold text-emerald-400">
              {dependencies.length}
            </span>
            <span className="text-xs text-gray-400">mapped links</span>
          </div>
          <p className="text-xs text-gray-500 mt-1">Cross-system architecture connections</p>
        </div>
      </div>

      {/* Main Interactive Blast Radius Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Target Selector, Vector Modes, & Containment Sandbox */}
        <div className="lg:col-span-4 space-y-6">
          {/* Target Asset Selector Card */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-sm space-y-4">
            <div>
              <label className="text-xs uppercase tracking-wider font-semibold text-gray-400 block mb-1">
                Select Compromised Asset
              </label>
              <select
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-medium focus:outline-none focus:border-blue-500"
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.hostname || a.ip_address || a.id} ({a.criticality.toUpperCase()} • {a.zone || "zone"})
                  </option>
                ))}
              </select>
            </div>

            {/* Target Quick Stats Pill */}
            {blastDetail?.asset && (
              <div className="bg-gray-950/80 border border-gray-800/80 rounded-lg p-3 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Criticality:</span>
                  <Badge value={blastDetail.asset.criticality} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Zone / Network:</span>
                  <span className="font-mono text-gray-200">{blastDetail.asset.zone || "unassigned"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">IP Address:</span>
                  <span className="font-mono text-gray-200">{blastDetail.asset.ip_address || "None"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Open Ports:</span>
                  <span className="font-semibold text-emerald-400">{blastDetail.asset.open_ports_count} detected</span>
                </div>
                <div className="flex items-center justify-between pt-1 border-t border-gray-800">
                  <span className="text-gray-400">Risk Tier:</span>
                  <Badge value={blastDetail.asset.priority_tier} />
                </div>
              </div>
            )}

            {/* Reachability Vector Mode Tabs */}
            <div>
              <label className="text-xs uppercase tracking-wider font-semibold text-gray-400 block mb-2">
                Reachability Mode
              </label>
              <div className="grid grid-cols-2 gap-1.5">
                {[
                  { id: "combined", label: "⚡ All Vectors", desc: "Subnet + Zone + Deps" },
                  { id: "same_subnet", label: "🌐 Same Subnet", desc: "Local /24 CIDR" },
                  { id: "same_zone", label: "🛡️ Same Zone", desc: "Security Boundary" },
                  { id: "dependency_edges", label: "🔗 Dependencies", desc: "Declared Links" },
                ].map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setMode(t.id as any)}
                    className={`p-2 rounded-lg border text-left transition ${
                      mode === t.id
                        ? "bg-blue-950/60 border-blue-500 text-blue-200 shadow-sm"
                        : "bg-gray-950 border-gray-800 text-gray-400 hover:text-gray-200 hover:border-gray-700"
                    }`}
                  >
                    <div className="font-semibold text-xs">{t.label}</div>
                    <div className="text-[10px] text-gray-500">{t.desc}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Containment Sandbox ("What-If" Analysis) */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-gray-100 flex items-center gap-1.5">
                  <span>🧪</span> Containment Sandbox
                </h3>
                <p className="text-[11px] text-gray-400">Simulate incident response & network isolation controls</p>
              </div>
              {(isolateSubnet || severDependencies || isolateZone) && (
                <button
                  onClick={() => {
                    setIsolateSubnet(false);
                    setSeverDependencies(false);
                    setIsolateZone(false);
                  }}
                  className="text-[10px] text-blue-400 hover:underline"
                >
                  Reset
                </button>
              )}
            </div>

            <div className="space-y-2.5">
              <label className="flex items-center justify-between p-2.5 rounded-lg bg-gray-950 border border-gray-800 hover:border-gray-700 cursor-pointer transition">
                <div className="space-y-0.5">
                  <span className="text-xs font-semibold text-gray-200 block">Isolate Subnet (PVLAN)</span>
                  <span className="text-[10px] text-gray-500 block">Blocks ARP & L2 lateral broadcast</span>
                </div>
                <input
                  type="checkbox"
                  checked={isolateSubnet}
                  onChange={(e) => setIsolateSubnet(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-gray-800 border-gray-700 focus:ring-blue-500"
                />
              </label>

              <label className="flex items-center justify-between p-2.5 rounded-lg bg-gray-950 border border-gray-800 hover:border-gray-700 cursor-pointer transition">
                <div className="space-y-0.5">
                  <span className="text-xs font-semibold text-gray-200 block">Sever Dependencies</span>
                  <span className="text-[10px] text-gray-500 block">Disconnect upstream API & RPC links</span>
                </div>
                <input
                  type="checkbox"
                  checked={severDependencies}
                  onChange={(e) => setSeverDependencies(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-gray-800 border-gray-700 focus:ring-blue-500"
                />
              </label>

              <label className="flex items-center justify-between p-2.5 rounded-lg bg-gray-950 border border-gray-800 hover:border-gray-700 cursor-pointer transition">
                <div className="space-y-0.5">
                  <span className="text-xs font-semibold text-gray-200 block">Quarantine Zone Enclave</span>
                  <span className="text-[10px] text-gray-500 block">Isolate into zero-trust containment cage</span>
                </div>
                <input
                  type="checkbox"
                  checked={isolateZone}
                  onChange={(e) => setIsolateZone(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-gray-800 border-gray-700 focus:ring-blue-500"
                />
              </label>
            </div>

            {/* Live Simulation Impact Card */}
            {simulationResult ? (
              <div className="bg-emerald-950/40 border border-emerald-800/80 rounded-lg p-3 space-y-2 animate-in fade-in">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-emerald-400">Risk Reduction Achieved:</span>
                  <span className="text-sm font-extrabold text-emerald-300">
                    -{simulationResult.impact.risk_reduction_pct}%
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs pt-1 border-t border-emerald-900/60">
                  <div>
                    <span className="text-gray-400 block text-[10px]">Blast Multiplier:</span>
                    <span className="font-mono text-gray-400 line-through mr-1">
                      {simulationResult.baseline.blast_radius_multiplier}x
                    </span>
                    <span className="font-mono font-bold text-emerald-300">
                      {simulationResult.simulated.blast_radius_multiplier}x
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-400 block text-[10px]">Mitigated Collateral:</span>
                    <span className="font-semibold text-emerald-300">
                      +{simulationResult.impact.mitigated_assets_count} systems saved
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-[11px] text-gray-500 text-center py-2 bg-gray-950/50 rounded border border-dashed border-gray-800">
                Toggle controls above to simulate containment efficacy.
              </div>
            )}
          </div>

          {/* Actionable Containment Directives */}
          {activeDetail?.recommendations && activeDetail.recommendations.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-sm space-y-2">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-gray-400 flex items-center gap-1.5">
                <span>🛡️</span> Containment Recommendations
              </h3>
              <ul className="space-y-2 text-xs text-gray-300">
                {activeDetail.recommendations.map((rec, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-blue-400 font-bold">•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Right Column: Visual Graph & Collateral Details */}
        <div className="lg:col-span-8 space-y-6">
          {/* Target Asset Exposure Banner */}
          {activeDetail && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-sm flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-gray-100">
                    {activeDetail.asset.hostname || activeDetail.asset.ip_address || activeDetail.asset.id}
                  </h2>
                  <span
                    className={`px-2 py-0.5 text-xs font-bold rounded ${
                      activeDetail.exposure_level === "Catastrophic"
                        ? "bg-red-950 text-red-400 border border-red-800"
                        : activeDetail.exposure_level === "High"
                        ? "bg-orange-950 text-orange-400 border border-orange-800"
                        : activeDetail.exposure_level === "Moderate"
                        ? "bg-yellow-950 text-yellow-400 border border-yellow-800"
                        : "bg-blue-950 text-blue-400 border border-blue-800"
                    }`}
                  >
                    {activeDetail.exposure_level} Exposure
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1">
                  Compromise of this asset exposes{" "}
                  <strong className="text-gray-200">{activeDetail.total_affected_count} collateral systems</strong> (
                  <span className="text-red-400 font-semibold">{activeDetail.criticality_breakdown.critical} critical</span>,{" "}
                  <span className="text-orange-400 font-semibold">{activeDetail.criticality_breakdown.high} high</span>,{" "}
                  <span className="text-yellow-400 font-semibold">{activeDetail.criticality_breakdown.medium} medium</span>).
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-[10px] text-gray-500 uppercase font-semibold">Active Blast Radius</p>
                  <p className="text-2xl font-black text-red-400">{activeDetail.blast_radius_multiplier}x</p>
                </div>
                <Link
                  href={`/assets/${activeDetail.asset.id}`}
                  className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs rounded-lg font-medium transition"
                >
                  View Asset →
                </Link>
              </div>
            </div>
          )}

          {/* Interactive Topology Graph Visualizer */}
          {activeDetail?.graph && (
            <BlastRadiusGraph
              nodes={activeDetail.graph.nodes}
              edges={activeDetail.graph.edges}
              targetAssetId={activeDetail.asset.id}
              onSelectNode={(nodeId) => setSelectedAssetId(nodeId)}
            />
          )}

          {/* Collateral Affected Assets Table */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-gray-100">
                  Collateral Assets in Blast Radius ({activeDetail?.reachable_assets.length || 0})
                </h3>
                <p className="text-xs text-gray-400">Direct and cascading targets reachable from {blastDetail?.asset.hostname || "the compromised host"}</p>
              </div>
              <span className="text-xs text-gray-500">Sorted by criticality & risk</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-gray-950/80 text-gray-400 text-left uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="px-4 py-3">Asset</th>
                    <th className="px-4 py-3">Criticality</th>
                    <th className="px-4 py-3">Reachability Vector</th>
                    <th className="px-4 py-3">Hop</th>
                    <th className="px-4 py-3">Exposed Ports</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {(activeDetail?.reachable_assets || []).map((ra) => (
                    <tr key={ra.id} className="hover:bg-gray-800/40 transition">
                      <td className="px-4 py-2.5">
                        <div className="font-semibold text-gray-200">
                          {ra.hostname || ra.ip_address || ra.id}
                        </div>
                        <div className="text-[10px] text-gray-500 font-mono">
                          {ra.ip_address || "No IP"} • {ra.zone || "unassigned"}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge value={ra.criticality} />
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {ra.vectors.map((vec) => (
                            <span
                              key={vec}
                              className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                                vec === "same_subnet"
                                  ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60"
                                  : vec === "same_zone"
                                  ? "bg-purple-950 text-purple-300 border border-purple-800/60"
                                  : "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                              }`}
                            >
                              {vec}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-gray-400">
                          {ra.hop === 1 ? "1st Direct" : "2nd Cascade"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        {ra.open_ports && ra.open_ports.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {ra.open_ports.slice(0, 3).map((p, idx) => (
                              <span key={idx} className="bg-gray-800 px-1.5 py-0.5 rounded font-mono text-[10px] text-gray-300">
                                {p.port}/{p.service || p.protocol}
                              </span>
                            ))}
                            {ra.open_ports.length > 3 && (
                              <span className="text-[10px] text-gray-500">+{ra.open_ports.length - 3}</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-500">-</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-right space-x-2">
                        <button
                          onClick={() => setSelectedAssetId(ra.id)}
                          className="px-2 py-1 text-[11px] rounded bg-blue-900/60 hover:bg-blue-800 text-blue-200 font-medium transition"
                        >
                          Pivot Focus
                        </button>
                        <Link
                          href={`/assets/${ra.id}`}
                          className="px-2 py-1 text-[11px] rounded border border-gray-700 hover:bg-gray-800 text-gray-300 transition"
                        >
                          Inspect
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {(!activeDetail?.reachable_assets || activeDetail.reachable_assets.length === 0) && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                        No collateral assets reachable from this host. Blast radius is contained.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Section: Organization-wide Blast Radius Ranking */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-sm space-y-4 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
              <span>🎯</span> Organization Lateral Risk Ranking
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Identifies the highest lateral pivot hazards in your infrastructure ordered by blast radius multiplier and crown-jewel exposure.
            </p>
          </div>
          <div className="w-full md:w-64">
            <input
              type="text"
              placeholder="Search assets..."
              value={assetSearchQuery}
              onChange={(e) => setAssetSearchQuery(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-gray-950/80 text-gray-400 text-left uppercase text-[10px] tracking-wider">
              <tr>
                <th className="px-4 py-3">Asset Name</th>
                <th className="px-4 py-3">Zone</th>
                <th className="px-4 py-3">Criticality</th>
                <th className="px-4 py-3">Blast Radius Factor</th>
                <th className="px-4 py-3">Collateral Assets</th>
                <th className="px-4 py-3">Critical Targets Exposed</th>
                <th className="px-4 py-3">Exposure Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {(overview?.ranked_assets || [])
                .filter((ra) => {
                  if (!assetSearchQuery) return true;
                  const q = assetSearchQuery.toLowerCase();
                  return (
                    ra.hostname?.toLowerCase().includes(q) ||
                    ra.ip_address?.toLowerCase().includes(q) ||
                    ra.zone?.toLowerCase().includes(q)
                  );
                })
                .map((ra) => {
                  const percent = Math.min(((ra.blast_radius_multiplier - 1.0) / 1.0) * 100, 100);
                  const isCurrent = ra.asset_id === selectedAssetId;

                  return (
                    <tr
                      key={ra.asset_id}
                      className={`hover:bg-gray-800/40 transition ${
                        isCurrent ? "bg-blue-950/20 border-l-2 border-l-blue-500" : ""
                      }`}
                    >
                      <td className="px-4 py-3 font-medium text-gray-200">
                        <div>{ra.hostname || ra.ip_address || ra.asset_id}</div>
                        <div className="text-[10px] text-gray-500 font-mono">{ra.ip_address || "No IP"}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-gray-400">{ra.zone || "-"}</td>
                      <td className="px-4 py-3">
                        <Badge value={ra.criticality} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-red-400 w-10">
                            {ra.blast_radius_multiplier}x
                          </span>
                          <div className="w-24 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className="bg-red-500 h-full rounded-full"
                              style={{ width: `${Math.max(percent, 8)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-semibold text-gray-300">
                        {ra.total_affected_count} systems
                      </td>
                      <td className="px-4 py-3">
                        {ra.critical_assets_at_risk > 0 ? (
                          <span className="text-red-400 font-bold flex items-center gap-1">
                            <span>⚠️</span> {ra.critical_assets_at_risk} critical
                          </span>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ra.exposure_level === "Catastrophic"
                              ? "text-red-400 bg-red-950/80 border border-red-800/60"
                              : ra.exposure_level === "High"
                              ? "text-orange-400 bg-orange-950/80 border border-orange-800/60"
                              : "text-blue-400 bg-blue-950/80 border border-blue-800/60"
                          }`}
                        >
                          {ra.exposure_level}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => {
                            setSelectedAssetId(ra.asset_id);
                            window.scrollTo({ top: 0, behavior: "smooth" });
                          }}
                          className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                            isCurrent
                              ? "bg-blue-600 text-white"
                              : "bg-gray-800 hover:bg-gray-700 text-gray-300"
                          }`}
                        >
                          {isCurrent ? "Active Focus" : "Analyze Radius"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Mapped Service Dependencies Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-sm space-y-4 p-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
              <span>🔗</span> Declared Service Dependencies ({dependencies.length})
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Directional graph edges representing architectural reliance and lateral compromise routes.
            </p>
          </div>
          <button
            onClick={() => setIsDepModalOpen(true)}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 text-xs rounded-lg font-medium transition flex items-center gap-1.5"
          >
            <span>+</span> Link Assets
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-gray-950/80 text-gray-400 text-left uppercase text-[10px] tracking-wider">
              <tr>
                <th className="px-4 py-3">Source Asset (Relying System)</th>
                <th className="px-4 py-3 text-center">Relationship</th>
                <th className="px-4 py-3">Target Asset (Dependency)</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {dependencies.map((dep) => (
                <tr key={dep.id} className="hover:bg-gray-800/40 transition">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-blue-400">
                      {dep.source_asset?.hostname || dep.source_asset?.ip_address || dep.asset_id}
                    </div>
                    <div className="text-[10px] text-gray-500">
                      {dep.source_asset?.criticality} • {dep.source_asset?.zone || "zone"}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className="font-mono text-gray-400 bg-gray-950 px-2 py-1 rounded border border-gray-800 text-[10px]">
                      ──depends on──▶
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-semibold text-emerald-400">
                      {dep.target_asset?.hostname || dep.target_asset?.ip_address || dep.depends_on_asset_id}
                    </div>
                    <div className="text-[10px] text-gray-500">
                      {dep.target_asset?.criticality} • {dep.target_asset?.zone || "zone"}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-[10px]">
                    {dep.created_at ? new Date(dep.created_at).toLocaleDateString() : "-"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDeleteDependency(dep.id)}
                      className="px-2 py-1 text-[11px] rounded border border-red-900/60 text-red-400 hover:bg-red-950/40 transition"
                    >
                      Unlink
                    </button>
                  </td>
                </tr>
              ))}
              {dependencies.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    No declared service dependencies mapped yet. Click &quot;+ Link Assets&quot; to establish architecture edges.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Declare Dependency Modal */}
      <DeclareDependencyModal
        assets={assets}
        defaultSourceAssetId={selectedAssetId}
        isOpen={isDepModalOpen}
        onClose={() => setIsDepModalOpen(false)}
        onSuccess={() => {
          loadInitialData();
          if (selectedAssetId) loadAssetBlastRadius(selectedAssetId, mode);
        }}
      />
    </div>
  );
}

export default function BlastRadiusPage() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-400 text-sm">Loading Blast Radius Workspace...</p>
        </div>
      }
    >
      <BlastRadiusContent />
    </Suspense>
  );
}

