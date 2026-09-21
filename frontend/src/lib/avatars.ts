export const AVATARS = [
  { id: "slate", label: "Kai", seed: "Kai" },
  { id: "forest", label: "Noa", seed: "Noa" },
  { id: "ocean", label: "Remy", seed: "Remy" },
  { id: "amber", label: "Sage", seed: "Sage" },
  { id: "rose", label: "Quinn", seed: "Quinn" },
  { id: "violet", label: "Ari", seed: "Ari" },
  { id: "graphite", label: "Blake", seed: "Blake" },
  { id: "mint", label: "Rowan", seed: "Rowan" },
] as const;

export function avatarMeta(id: string) {
  return AVATARS.find((item) => item.id === id) || AVATARS[0];
}

export function avatarUrl(id: string) {
  const { seed } = avatarMeta(id);
  return `https://api.dicebear.com/9.x/notionists/svg?seed=${encodeURIComponent(seed)}&backgroundColor=e8eef2,e7f0ec,efe8f4,f3ece4,e8eef8`;
}

export function formatStatus(status: string) {
  return (status || "").replace(/_/g, " ");
}
