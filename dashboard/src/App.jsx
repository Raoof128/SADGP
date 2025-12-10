import React, { useEffect, useMemo, useState } from "react";

const syntheticEvents = [
  {
    session_id: "s1",
    user_id: "alice",
    target_service: "OpenAI",
    action: "redact",
    risk_score: 0.6,
    policy_triggered: ["RULE_NO_PII"],
    notes: ["PII detected", "redaction applied"],
  },
  {
    session_id: "s2",
    user_id: "bob",
    target_service: "Anthropic",
    action: "block",
    risk_score: 0.9,
    policy_triggered: ["RULE_BLOCK_EXTERNAL"],
    notes: ["External LLM not whitelisted"],
  },
];

function useSyntheticFeed() {
  const [events, setEvents] = useState(syntheticEvents);
  useEffect(() => {
    const id = setInterval(() => {
      setEvents((prev) => [
        ...prev.slice(-9),
        {
          ...syntheticEvents[0],
          session_id: `s-${Date.now()}`,
          risk_score: Math.random(),
        },
      ]);
    }, 5000);
    return () => clearInterval(id);
  }, []);
  return events;
}

function Heatmap({ stats }) {
  return (
    <div className="panel">
      <h3>AI Service Usage</h3>
      <div className="heatmap">
        {Object.entries(stats).map(([service, count]) => (
          <div key={service} className="heatmap-cell">
            <span>{service}</span>
            <strong>{count}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function Violations({ events }) {
  return (
    <div className="panel">
      <h3>Policy Violations</h3>
      <ul className="list">
        {events.map((e) => (
          <li key={e.session_id}>
            <div>
              <strong>{e.target_service}</strong> – {e.action}
            </div>
            <div className="muted">{e.policy_triggered.join(", ")}</div>
            <div className="muted">Risk: {(e.risk_score * 100).toFixed(0)}%</div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Logs({ events }) {
  return (
    <div className="panel">
      <h3>Redaction Logs</h3>
      <ul className="list">
        {events.map((e) => (
          <li key={e.session_id}>
            <div>
              Session {e.session_id} – {e.notes.join("; ")}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function App() {
  const events = useSyntheticFeed();
  const stats = useMemo(() => {
    const counts = {};
    for (const e of events) {
      counts[e.target_service] = (counts[e.target_service] || 0) + 1;
    }
    return counts;
  }, [events]);

  return (
    <div className="page">
      <header>
        <h1>Shadow AI Governance Dashboard</h1>
        <p>Live synthetic feed of policy decisions (demo only)</p>
      </header>
      <main className="grid">
        <Heatmap stats={stats} />
        <Violations events={events.slice(-5).reverse()} />
        <Logs events={events.slice(-5).reverse()} />
      </main>
    </div>
  );
}

