"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Asset } from "@/lib/types";
import { Badge } from "@/components/Badge";
import { DeclareAssetModal } from "@/components/DeclareAssetModal";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [zoneFilter, setZoneFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [showDeclareModal, setShowDeclareModal] = useState(false);

  useEffect(() => {
    loadAssets();
  }, [statusFilter, zoneFilter, searchQuery]);

  async function loadAssets() {
    setLoading(true);
    try {
      const filters: { asset_status?: string; zone?: string; q?: string } = {};
      if (statusFilter) filters.asset_status = statusFilter;
      if (zoneFilter) filters.zone = zoneFilter;
      if (searchQuery) filters.q = searchQuery;
      const result = await api.listAssets(filters);
      setAssets(result?.assets || []);
    } catch (err) {
      console.warn("Failed to load assets:", err);
    } finally {
      setLoading(false);
    }
  }

  async function confirm(assetId: string) {
    try {
      await api.confirmAsset(assetId);
      await loadAssets();
    } catch (err) {
      console.error("Failed to confirm asset:", err);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Assets Inventory</h1>
          <p className="text-xs text-gray-400">Discovered external targets and declared internal endpoints/servers.</p>
        </div>
        <button
          onClick={() => setShowDeclareModal(true)}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded font-medium"
        >
          + Declare Asset
        </button>
      </div>

      <div className="flex flex-wrap gap-2 items-center bg-gray-900 border border-gray-800 rounded p-3">
        <input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search by hostname, IP or type..."
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm flex-1 min-w-[200px]"
        />

        <select
          value={zoneFilter}
          onChange={(e) => setZoneFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="">All Zones</option>
          <option value="external">External</option>
          <option value="internal">Internal</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="">All Statuses</option>
          <option value="discovered">Discovered</option>
          <option value="declared">Declared</option>
          <option value="confirmed">Confirmed</option>
        </select>
      </div>

      {loading ? (
        <p className="text-gray-400">Loading assets...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Hostname / IP</th>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Zone</th>
                <th className="px-4 py-2">Criticality</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2">
                    <Link href={`/assets/${asset.id}`} className="text-blue-400 hover:underline font-medium">
                      {asset.hostname || asset.ip_address || asset.id}
                    </Link>
                    {asset.hostname && asset.ip_address && (
                      <span className="text-xs text-gray-500 block">{asset.ip_address}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-gray-400 font-mono text-xs">{asset.asset_type || "-"}</td>
                  <td className="px-4 py-2 text-gray-400">{asset.zone || "-"}</td>
                  <td className="px-4 py-2 text-gray-400">
                    <Badge value={asset.criticality} />
                  </td>
                  <td className="px-4 py-2">
                    <Badge value={asset.asset_status} />
                  </td>
                  <td className="px-4 py-2 text-right">
                    {asset.asset_status === "discovered" && (
                      <button
                        onClick={() => confirm(asset.id)}
                        className="text-xs px-2 py-1 bg-blue-700 hover:bg-blue-600 text-white rounded"
                      >
                        Confirm
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {assets.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                    No assets found matching the criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showDeclareModal && (
        <DeclareAssetModal onClose={() => setShowDeclareModal(false)} onCreated={loadAssets} />
      )}
    </div>
  );
}
