import {
  Cloud,
  Database,
  FileText,
  Globe,
  KeyRound,
  Monitor,
  Server,
  ShieldCheck,
  Terminal,
  type LucideIcon,
} from "lucide-react";

/** One icon per record type. A DevOps engineer scans by shape, not by reading. */
export const TYPE_ICONS: Record<string, LucideIcon> = {
  ssh_server: Server,
  rdp_host: Monitor,
  api_key: KeyRound,
  cloud_service_account: Cloud,
  web_login: Globe,
  database: Database,
  certificate: ShieldCheck,
  command_snippet: Terminal,
  secure_note: FileText,
};

export function iconFor(recordType: string): LucideIcon {
  return TYPE_ICONS[recordType] ?? FileText;
}

export function relativeTime(unix: number | null): string {
  if (!unix) return "never";
  const seconds = Math.floor(Date.now() / 1000) - unix;
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
