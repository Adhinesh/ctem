"use client";

import React, { useState, useMemo } from "react";
import { BlastRadiusNode, BlastRadiusEdge } from "@/lib/types";
import { Badge } from "@/components/Badge";

interface BlastRadiusGraphProps {
  nodes: BlastRadiusNode[];
  edges: BlastRadiusEdge[];
  targetAssetId: string;
  onSelectNode: (assetId: string) => void;
}

export function BlastRadiusGraph({
  nodes,
  edges,
  targetAssetId,
  onSelectNode,
}: BlastRadiusGraphProps) {
  const [hoveredNode, setHoveredNode] = useState<BlastRadiusNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selectedVectorFilter, setSelectedVectorFilter] = useState<string>("all");

  const width = 800;
  const height = 620;
  const centerX = width / 2;
  const centerY = height / 2;

  // Filter edges and reachable nodes based on vector filter
  const filteredEdges = useMemo(() => {
    if (selectedVectorFilter === "all") return edges;
    return edges.filter((e) => {
      if (selectedVectorFilter === "subnet") return e.vector === "same_subnet";
      if (selectedVectorFilter === "zone") return e.vector === "same_zone";
      if (selectedVectorFilter === "dependency") return e.vector.includes("dependency");
      return true;
    });
  }, [edges, selectedVectorFilter]);

  const activeReachableIds = useMemo(() => {
    const ids = new Set<string>();
    filteredEdges.forEach((e) => {
      ids.add(e.to_asset_id);
      ids.add(e.from_asset_id);
    });
    return ids;
  }, [filteredEdges]);

  // Separate target, 1st hop, and 2nd hop nodes
  const { targetNode, hop1Nodes, hop2Nodes } = useMemo<{
    targetNode: BlastRadiusNode | null;
    hop1Nodes: BlastRadiusNode[];
    hop2Nodes: BlastRadiusNode[];
  }>(() => {
    let target: BlastRadiusNode | null = null;
    const h1: BlastRadiusNode[] = [];
    const h2: BlastRadiusNode[] = [];

    nodes.forEach((n) => {
      if (n.id === targetAssetId || n.is_target) {
        target = n;
      } else if (selectedVectorFilter === "all" || activeReachableIds.has(n.id)) {
        if (n.hop === 1) {
          h1.push(n);
        } else {
          h2.push(n);
        }
      }
    });

    return { targetNode: target, hop1Nodes: h1, hop2Nodes: h2 };
  }, [nodes, targetAssetId, selectedVectorFilter, activeReachableIds]);

  // Compute radial layout coordinates
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    if (targetNode) {
      const tNode = targetNode as BlastRadiusNode;
      positions[tNode.id] = { x: centerX, y: centerY };
    }

    const r1 = 175;
    const count1 = hop1Nodes.length;
    hop1Nodes.forEach((n, idx) => {
      const angle = (2 * Math.PI * idx) / (count1 || 1) - Math.PI / 2;
      positions[n.id] = {
        x: centerX + r1 * Math.cos(angle),
        y: centerY + r1 * Math.sin(angle),
      };
    });

    const r2 = 270;
    const count2 = hop2Nodes.length;
    hop2Nodes.forEach((n, idx) => {
      const angle = (2 * Math.PI * idx) / (count2 || 1) - Math.PI / 4;
      positions[n.id] = {
        x: centerX + r2 * Math.cos(angle),
        y: centerY + r2 * Math.sin(angle),
      };
    });

    return positions;
  }, [targetNode, hop1Nodes, hop2Nodes, centerX, centerY]);

  const getCriticalityColor = (crit: string) => {
    switch (crit?.toLowerCase()) {
      case "critical":
        return "#ef4444"; // red-500
      case "high":
        return "#f97316"; // orange-500
      case "medium":
        return "#eab308"; // yellow-500
      case "low":
      default:
        return "#3b82f6"; // blue-500
    }
  };

  const getVectorStroke = (vector: string) => {
    if (vector === "same_subnet") return "#06b6d4"; // cyan
    if (vector === "same_zone") return "#a855f7"; // purple
    if (vector.includes("dependency")) return "#10b981"; // emerald
    return "#64748b"; // slate
  };

  return (
    <div className="relative bg-gray-950 border border-gray-800 rounded-xl overflow-hidden shadow-2xl">
      {/* Top Interactive Controls & Legend */}
      <div className="p-4 border-b border-gray-800/80 bg-gray-900/60 backdrop-blur flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-gray-400 font-medium">Filter Vector:</span>
          {[
            { id: "all", label: "All Vectors" },
            { id: "subnet", label: "Subnet (/24)" },
            { id: "zone", label: "Zone" },
            { id: "dependency", label: "Dependencies" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedVectorFilter(tab.id)}
              className={`px-2.5 py-1 rounded transition-colors ${
                selectedVectorFilter === tab.id
                  ? "bg-blue-600 text-white font-medium shadow-sm"
                  : "bg-gray-800/80 text-gray-400 hover:text-gray-200 hover:bg-gray-800"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-4 text-gray-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping inline-block" />
            <span className="text-red-400 font-medium">Target Node</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Subnet</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span>Zone</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>Dependency</span>
          </div>
          <div className="flex items-center gap-1 ml-2">
            <button
              onClick={() => setZoom((z) => Math.min(z + 0.15, 1.6))}
              className="w-6 h-6 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 flex items-center justify-center font-bold"
              title="Zoom In"
            >
              +
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(z - 0.15, 0.7))}
              className="w-6 h-6 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 flex items-center justify-center font-bold"
              title="Zoom Out"
            >
              -
            </button>
            <button
              onClick={() => setZoom(1)}
              className="px-2 h-6 rounded bg-gray-800 hover:bg-gray-700 text-gray-400 text-[10px]"
              title="Reset Zoom"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative overflow-hidden flex items-center justify-center py-4 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900/40 via-gray-950 to-gray-950">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full max-h-[640px] select-none transition-transform duration-300"
          style={{ transform: `scale(${zoom})`, transformOrigin: "center center" }}
        >
          <defs>
            {/* Glow Filter */}
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>

            {/* Target Pulse Glow */}
            <filter id="target-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="8" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>

            {/* Arrowhead Markers */}
            <marker id="arrow-subnet" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#06b6d4" />
            </marker>
            <marker id="arrow-zone" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#a855f7" />
            </marker>
            <marker id="arrow-dependency" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
            </marker>
            <marker id="arrow-default" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
          </defs>

          {/* Background Concentric Radar Rings */}
          <g className="opacity-25 pointer-events-none">
            {/* 1st Hop Direct Orbit */}
            <circle cx={centerX} cy={centerY} r={175} fill="none" stroke="#3b82f6" strokeWidth="1.5" strokeDasharray="6 6" />
            <text x={centerX} y={centerY - 182} textAnchor="middle" fill="#60a5fa" fontSize="10" fontWeight="600" letterSpacing="1">
              DIRECT BLAST RADIUS (1ST-HOP)
            </text>

            {/* 2nd Hop Cascade Orbit */}
            <circle cx={centerX} cy={centerY} r={270} fill="none" stroke="#6366f1" strokeWidth="1" strokeDasharray="4 8" />
            <text x={centerX} y={centerY - 277} textAnchor="middle" fill="#818cf8" fontSize="10" fontWeight="500" letterSpacing="1">
              CASCADE LATERAL EXPOSURE (2ND-HOP)
            </text>
          </g>

          {/* Edges / Attack Paths */}
          <g>
            {filteredEdges.map((edge, idx) => {
              const fromPos = nodePositions[edge.from_asset_id];
              const toPos = nodePositions[edge.to_asset_id];
              if (!fromPos || !toPos) return null;

              const strokeColor = getVectorStroke(edge.vector);
              let markerId = "arrow-default";
              if (edge.vector === "same_subnet") markerId = "arrow-subnet";
              else if (edge.vector === "same_zone") markerId = "arrow-zone";
              else if (edge.vector.includes("dependency")) markerId = "arrow-dependency";

              const isHighlighted =
                hoveredNode &&
                (hoveredNode.id === edge.from_asset_id || hoveredNode.id === edge.to_asset_id);

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={fromPos.x}
                    y1={fromPos.y}
                    x2={toPos.x}
                    y2={toPos.y}
                    stroke={strokeColor}
                    strokeWidth={isHighlighted ? 3 : edge.hop === 1 ? 2 : 1.25}
                    strokeDasharray={edge.hop === 2 ? "4 4" : undefined}
                    strokeOpacity={isHighlighted ? 0.95 : 0.45}
                    markerEnd={`url(#${markerId})`}
                    className="transition-all duration-200"
                  />
                </g>
              );
            })}
          </g>

          {/* Reachable Nodes */}
          <g>
            {[...hop1Nodes, ...hop2Nodes].map((node) => {
              const pos = nodePositions[node.id];
              if (!pos) return null;

              const isHovered = hoveredNode?.id === node.id;
              const critColor = getCriticalityColor(node.criticality);

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => onSelectNode(node.id)}
                  className="cursor-pointer transition-transform duration-200 hover:scale-110"
                >
                  {/* Outer Criticality Ring */}
                  <circle
                    r={isHovered ? 21 : 17}
                    fill="#0f172a"
                    stroke={critColor}
                    strokeWidth={isHovered ? 3.5 : 2}
                    filter={isHovered ? "url(#glow)" : undefined}
                  />

                  {/* Inner Status Core */}
                  <circle r={8} fill={critColor} fillOpacity={0.8} />

                  {/* Ports indicator dot if any */}
                  {node.ports_count > 0 && (
                    <circle cx={12} cy={-12} r={5} fill="#10b981" stroke="#0f172a" strokeWidth={1.5} />
                  )}

                  {/* Node Label */}
                  <text
                    y={28}
                    textAnchor="middle"
                    fill="#e2e8f0"
                    fontSize="11"
                    fontWeight="500"
                    className="pointer-events-none drop-shadow-md"
                  >
                    {node.label.length > 16 ? node.label.slice(0, 14) + "…" : node.label}
                  </text>
                  <text
                    y={40}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                    className="pointer-events-none"
                  >
                    {node.ip_address || node.criticality}
                  </text>
                </g>
              );
            })}
          </g>

          {/* Center Target Node */}
          {targetNode && (
            <g
              transform={`translate(${centerX}, ${centerY})`}
              onMouseEnter={() => setHoveredNode(targetNode)}
              onMouseLeave={() => setHoveredNode(null)}
              className="cursor-pointer"
            >
              {/* Pulsing Alert Waves */}
              <circle r={46} fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-ping opacity-30" />
              <circle r={36} fill="#7f1d1d" fillOpacity="0.3" stroke="#ef4444" strokeWidth="2.5" filter="url(#target-glow)" />

              {/* Core Node Circle */}
              <circle r={28} fill="#991b1b" stroke="#fca5a5" strokeWidth="2" />

              {/* Crosshair / Hazard Symbol */}
              <path
                d="M -10 0 L 10 0 M 0 -10 L 0 10 M -6 -6 L 6 6 M -6 6 L 6 -6"
                stroke="#fee2e2"
                strokeWidth="2"
                strokeLinecap="round"
              />

              {/* Target Label */}
              <text y={44} textAnchor="middle" fill="#f87171" fontSize="12" fontWeight="700" letterSpacing="0.5">
                PRIMARY TARGET
              </text>
              <text y={58} textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="600">
                {targetNode.label.length > 20 ? targetNode.label.slice(0, 18) + "…" : targetNode.label}
              </text>
            </g>
          )}
        </svg>

        {/* Empty state overlay if isolated */}
        {hop1Nodes.length === 0 && hop2Nodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center bg-gray-950/70 backdrop-blur-sm pointer-events-none">
            <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl text-center max-w-sm shadow-xl">
              <span className="text-3xl mb-2 block">🛡️</span>
              <h3 className="text-base font-semibold text-gray-200">Zero Lateral Reachability</h3>
              <p className="text-xs text-gray-400 mt-1">
                No collateral assets detected under the selected filter ({selectedVectorFilter}). This asset is strictly segmented.
              </p>
            </div>
          </div>
        )}

        {/* Hover Inspection Tooltip Card */}
        {hoveredNode && (
          <div className="absolute bottom-4 left-4 bg-gray-900/95 border border-gray-700/80 rounded-lg p-3 shadow-2xl backdrop-blur max-w-xs text-xs pointer-events-none z-20">
            <div className="flex items-center justify-between gap-2 mb-1.5 border-b border-gray-800 pb-1.5">
              <span className="font-semibold text-gray-100 truncate">{hoveredNode.label}</span>
              <Badge value={hoveredNode.criticality} />
            </div>
            <div className="space-y-1 text-gray-300">
              <div className="flex justify-between">
                <span className="text-gray-500">IP Address:</span>
                <span className="font-mono text-gray-200">{hoveredNode.ip_address || "None"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Zone:</span>
                <span className="font-mono text-gray-200">{hoveredNode.zone || "unassigned"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Risk Score:</span>
                <span className="font-semibold text-amber-400">{hoveredNode.composite_score}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Open Ports:</span>
                <span className="font-medium text-emerald-400">{hoveredNode.ports_count} active</span>
              </div>
              {hoveredNode.vectors && hoveredNode.vectors.length > 0 && (
                <div className="pt-1 border-t border-gray-800">
                  <span className="text-gray-500 block mb-0.5">Reachability Vectors:</span>
                  <div className="flex flex-wrap gap-1">
                    {hoveredNode.vectors.map((v) => (
                      <span key={v} className="px-1.5 py-0.5 rounded bg-blue-950 border border-blue-800/60 text-[10px] text-blue-300">
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <p className="mt-2 text-[10px] text-blue-400 font-medium">Click node to pivot Blast Radius focus →</p>
          </div>
        )}
      </div>

      {/* Footer hint */}
      <div className="px-4 py-2.5 bg-gray-900 border-t border-gray-800/80 text-[11px] text-gray-400 flex items-center justify-between">
        <span>
          Showing <strong className="text-gray-200">{hop1Nodes.length}</strong> direct and{" "}
          <strong className="text-gray-200">{hop2Nodes.length}</strong> cascade collateral assets.
        </span>
        <span className="text-gray-500">Click any asset node to pivot analysis</span>
      </div>
    </div>
  );
}
