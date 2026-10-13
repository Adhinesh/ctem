"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/scans", label: "Scans" },
  { href: "/assets", label: "Assets" },
  { href: "/blast-radius", label: "Blast Radius" },
  { href: "/alerts", label: "Alerts" },
  { href: "/peripherals", label: "Peripherals" },
  { href: "/monitoring", label: "Monitoring & Logs" },
];

export function NavBar() {
  const pathname = usePathname();

  return (
    <nav className="border-b border-gray-800 bg-gray-950 px-6 py-3 flex items-center gap-6">
      <span className="text-lg font-semibold text-gray-100">CTEM Platform</span>
      <div className="flex gap-4">
        {links.map((link) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={link.href}
              className={
                active
                  ? "text-sm font-medium text-blue-400"
                  : "text-sm font-medium text-gray-400 hover:text-gray-200"
              }
            >
              {link.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
