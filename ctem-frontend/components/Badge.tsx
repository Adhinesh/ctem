const COLORS: Record<string, string> = {
  P1: "bg-red-600 text-white",
  critical: "bg-red-600 text-white",
  P2: "bg-orange-500 text-white",
  high: "bg-orange-500 text-white",
  P3: "bg-yellow-500 text-black",
  medium: "bg-yellow-500 text-black",
  P4: "bg-blue-600 text-white",
  low: "bg-gray-600 text-white",
  open: "bg-red-600 text-white",
  acknowledged: "bg-yellow-500 text-black",
  resolved: "bg-green-600 text-white",
  complete: "bg-green-600 text-white",
  failed: "bg-red-600 text-white",
  queued: "bg-gray-600 text-white",
  running: "bg-blue-600 text-white",
  ingesting: "bg-blue-600 text-white",
  scoring: "bg-blue-600 text-white",
};

export function Badge({ value }: { value: string }) {
  const classes = COLORS[value] || "bg-gray-700 text-gray-100";
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold ${classes}`}>{value}</span>;
}
