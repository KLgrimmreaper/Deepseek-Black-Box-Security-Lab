export type ViewId = "overview" | "runs" | "catalogue" | "findings" | "settings";

const ICONS: Record<ViewId, string[]> = {
  overview: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M3 14h7v7H3z", "M14 14h7v7h-7z"],
  runs: ["M4 6h16", "M4 12h16", "M4 18h10"],
  catalogue: ["M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z"],
  findings: ["M12 4l9 16H3z", "M12 10v4", "M12 17h.01"],
  settings: ["M4 8h8", "M16 8h4", "M4 16h4", "M12 16h8", "M14 6v4", "M10 14v4"],
};

const GROUPS: { label: string; items: { id: ViewId; name: string }[] }[] = [
  {
    label: "core tools",
    items: [
      { id: "overview", name: "Overview" },
      { id: "runs", name: "Runs" },
      { id: "catalogue", name: "Check Catalogue" },
    ],
  },
  {
    label: "results",
    items: [{ id: "findings", name: "Findings" }],
  },
  {
    label: "platform",
    items: [{ id: "settings", name: "Settings" }],
  },
];

type Props = {
  view: ViewId;
  onSelect: (view: ViewId) => void;
  counts: Partial<Record<ViewId, number>>;
};

export default function Sidebar({ view, onSelect, counts }: Props) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <svg viewBox="0 0 24 24" className="brand-mark" aria-hidden="true">
          <path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <div>
          <strong>dsh lab</strong>
          <span className="brand-sub">black-box security lab</span>
        </div>
      </div>

      {GROUPS.map((group) => (
        <div className="nav-group" key={group.label}>
          <span className="nav-label">{group.label}</span>
          {group.items.map((item) => (
            <button
              key={item.id}
              type="button"
              className={item.id === view ? "nav-item active" : "nav-item"}
              onClick={() => onSelect(item.id)}
            >
              <svg viewBox="0 0 24 24" className="nav-icon" aria-hidden="true">
                {ICONS[item.id].map((path) => (
                  <path key={path} d={path} />
                ))}
              </svg>
              <span>{item.name}</span>
              {counts[item.id] !== undefined && <span className="nav-count">{counts[item.id]}</span>}
            </button>
          ))}
        </div>
      ))}

      <div className="sidebar-footer">
        local lab only
        <span>checks are limited to ALLOWED_TARGETS</span>
      </div>
    </aside>
  );
}
