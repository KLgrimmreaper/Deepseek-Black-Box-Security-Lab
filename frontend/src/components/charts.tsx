type StatProps = {
  label: string;
  value: number | string;
  hint?: string;
  accent?: string;
};

export function StatCard({ label, value, hint, accent }: StatProps) {
  return (
    <div className="card stat" style={accent ? { borderTopColor: accent } : undefined}>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

type Segment = { label: string; value: number; color: string };

export function Donut({ segments, caption }: { segments: Segment[]; caption: string }) {
  const size = 190;
  const stroke = 22;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  let offset = 0;

  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="donut" role="img" aria-label={`${total} ${caption}`}>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1b2438" strokeWidth={stroke} />
      {segments.map((segment) => {
        const length = total > 0 ? (segment.value / total) * circumference : 0;
        const dash = `${length} ${circumference - length}`;
        const circle = (
          <circle
            key={segment.label}
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={segment.color}
            strokeWidth={stroke}
            strokeDasharray={dash}
            strokeDashoffset={-offset}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        );
        offset += length;
        return circle;
      })}
      <text x="50%" y="48%" textAnchor="middle" className="donut-total">
        {total}
      </text>
      <text x="50%" y="60%" textAnchor="middle" className="donut-caption">
        {caption}
      </text>
    </svg>
  );
}

type Point = { label: string; value: number };

export function AreaChart({ points }: { points: Point[] }) {
  if (points.length < 2) {
    return <p className="hint">the chart appears once there are two or more runs to compare</p>;
  }
  const width = 720;
  const height = 220;
  const padX = 12;
  const floor = 26;
  const ceiling = height - 26;
  // scale to a bit more than the biggest value so a flat run does not fill the whole panel
  const peak = Math.max(...points.map((point) => point.value), 1) * 1.25;
  const stepX = (width - padX * 2) / (points.length - 1);
  const y = (value: number) => ceiling - (value / peak) * (ceiling - floor);
  const coords = points.map((point, index) => [padX + index * stepX, y(point.value)] as const);
  const line = coords.map(([x, py]) => `${x},${py}`).join(" ");
  const area = `${coords[0][0]},${ceiling} ${line} ${coords[coords.length - 1][0]},${ceiling}`;
  const gridlines = [0, 0.25, 0.5, 0.75, 1].map((fraction) => ceiling - fraction * (ceiling - floor));

  return (
    <div className="chart-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} className="chart" preserveAspectRatio="none">
        <defs>
          <linearGradient id="area-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4d7cfe" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#4d7cfe" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <polygon points={area} fill="url(#area-fill)" />
        {gridlines.map((gridY) => (
          <line key={gridY} x1={0} y1={gridY} x2={width} y2={gridY} className="grid" />
        ))}
        <polyline points={line} className="line" />
        {coords.map(([x, py], index) => (
          <circle key={index} cx={x} cy={py} r={4} className="dot" />
        ))}
      </svg>
      <div className="chart-labels">
        {points.map((point, index) => (
          <span key={index}>{points.length <= 8 || index % 2 === 0 ? point.label : ""}</span>
        ))}
      </div>
    </div>
  );
}

type Bar = { label: string; value: number; color?: string };

export function BarList({ items, emptyText }: { items: Bar[]; emptyText: string }) {
  if (items.length === 0) {
    return <p className="hint">{emptyText}</p>;
  }
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <ul className="bars">
      {items.map((item) => (
        <li key={item.label}>
          <div className="bar-head">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{ width: `${(item.value / max) * 100}%`, background: item.color }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}
