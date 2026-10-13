export type ScanStatus = "queued" | "running" | "ingesting" | "scoring" | "complete" | "failed";

export interface Scan {
  scan_id: string;
  target: string;
  target_type: string;
  status: ScanStatus;
  labels: Record<string, any>;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  error_message: string | null;
}

export interface OpenPort {
  id?: string;
  asset_id?: string;
  port: string;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  created_at?: string;
}

export interface Asset {
  id: string;
  hostname: string | null;
  ip_address: string | null;
  cidr: string | null;
  asset_type: string | null;
  zone: "internal" | "external" | null;
  criticality: "low" | "medium" | "high" | "critical";
  asset_status: "discovered" | "declared" | "confirmed";
  asset_confirmed: boolean;
  declared_by?: string | null;
  declared_at?: string | null;
  open_ports?: OpenPort[];
  open_ports_count?: number;
  highest_tier?: "P1" | "P2" | "P3" | "P4" | null;
  max_score?: number | null;
  created_at: string;
}

export interface RiskScore {
  id: string;
  asset_id: string;
  cve_id: string;
  matched_product: string | null;
  matched_version: string | null;
  composite_score: number;
  priority_tier: "P1" | "P2" | "P3" | "P4";
  sla_hours: number;
  criticality_mismatch: boolean;
}

export interface HeatmapEntry {
  asset_id: string;
  hostname: string | null;
  zone: string | null;
  composite_score: number;
  priority_tier: string;
  findings_count?: number;
  last_assessed?: string | null;
}

export interface Alert {
  id: string;
  alert_type: string;
  title: string;
  description: string | null;
  severity: "low" | "medium" | "high" | "critical";
  asset_id: string | null;
  status: "open" | "acknowledged" | "resolved";
  created_at: string;
}

export interface Peripheral {
  id: string;
  device_type: string;
  serial_number: string | null;
  device_identifier: string | null;
  label: string | null;
  ip_address: string | null;
  authorized: boolean;
  authorized_by?: string | null;
  authorized_at?: string | null;
}

export interface SecurityEvent {
  id: string;
  source: string;
  asset_id: string | null;
  event_type: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string | null;
  occurred_at: string;
  created_at?: string;
}

export interface UebaEvent {
  id: string;
  username: string;
  event_type: string;
  source_ip: string | null;
  occurred_at: string;
  created_at?: string;
}

export interface BlastRadiusNode {
  id: string;
  label: string;
  ip_address: string | null;
  zone: string | null;
  criticality: "low" | "medium" | "high" | "critical";
  asset_type: string | null;
  is_target: boolean;
  hop: number;
  vectors?: string[];
  composite_score: number;
  priority_tier: string;
  ports_count: number;
}

export interface BlastRadiusEdge {
  from_asset_id: string;
  to_asset_id: string;
  hop: number;
  vector: string;
  description: string;
}

export interface BlastRadiusReachableAsset {
  id: string;
  hostname: string | null;
  ip_address: string | null;
  zone: string | null;
  criticality: "low" | "medium" | "high" | "critical";
  asset_type: string | null;
  asset_status: string;
  hop: number;
  vectors: string[];
  composite_score: number;
  priority_tier: string;
  open_ports_count: number;
  open_ports?: OpenPort[];
}

export interface BlastRadiusDetail {
  asset: {
    id: string;
    hostname: string | null;
    ip_address: string | null;
    zone: string | null;
    criticality: "low" | "medium" | "high" | "critical";
    asset_type: string | null;
    asset_status: string;
    composite_score: number;
    priority_tier: string;
    open_ports_count: number;
    open_ports: OpenPort[];
  };
  reachability_mode: "combined" | "same_subnet" | "same_zone" | "dependency_edges";
  blast_radius_multiplier: number;
  direct_reachable_count: number;
  cascade_reachable_count: number;
  total_affected_count: number;
  exposure_level: "Catastrophic" | "High" | "Moderate" | "Contained";
  criticality_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  reachable_assets: BlastRadiusReachableAsset[];
  attack_paths: BlastRadiusEdge[];
  graph: {
    nodes: BlastRadiusNode[];
    edges: BlastRadiusEdge[];
  };
  recommendations: string[];
  simulation_state: {
    isolate_subnet: boolean;
    sever_dependencies: boolean;
    isolate_zone: boolean;
  };
}

export interface BlastRadiusSummaryItem {
  asset_id: string;
  hostname: string | null;
  ip_address: string | null;
  zone: string | null;
  criticality: "low" | "medium" | "high" | "critical";
  asset_type: string | null;
  blast_radius_multiplier: number;
  direct_reachable_count: number;
  total_affected_count: number;
  exposure_level: "Catastrophic" | "High" | "Moderate" | "Contained";
  critical_assets_at_risk: number;
  high_assets_at_risk: number;
}

export interface BlastRadiusOverview {
  reachability_mode: string;
  total_assets: number;
  total_dependencies: number;
  avg_blast_radius: number;
  highest_blast_radius: number;
  assets_with_critical_exposure: number;
  ranked_assets: BlastRadiusSummaryItem[];
}

export interface BlastRadiusSimulation {
  asset_id: string;
  controls_applied: {
    isolate_subnet: boolean;
    sever_dependencies: boolean;
    isolate_zone: boolean;
  };
  baseline: {
    blast_radius_multiplier: number;
    total_affected_count: number;
    direct_reachable_count: number;
    critical_assets_at_risk: number;
    exposure_level: string;
  };
  simulated: {
    blast_radius_multiplier: number;
    total_affected_count: number;
    direct_reachable_count: number;
    critical_assets_at_risk: number;
    exposure_level: string;
  };
  impact: {
    mitigated_assets_count: number;
    risk_reduction_pct: number;
    multiplier_reduction: number;
  };
  simulated_blast_radius: BlastRadiusDetail;
}

export interface AssetDependency {
  id: string;
  asset_id: string;
  depends_on_asset_id: string;
  created_at?: string;
  source_asset: {
    id: string;
    hostname: string | null;
    ip_address: string | null;
    zone: string | null;
    criticality: "low" | "medium" | "high" | "critical";
    asset_type: string | null;
  };
  target_asset: {
    id: string;
    hostname: string | null;
    ip_address: string | null;
    zone: string | null;
    criticality: "low" | "medium" | "high" | "critical";
    asset_type: string | null;
  };
}

