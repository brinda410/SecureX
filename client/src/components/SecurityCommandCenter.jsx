import { useCallback, useEffect, useState } from "react";
import EncryptionVerificationPanel from "./EncryptionVerificationPanel";

const API_URL = (
  import.meta.env.VITE_API_URL || "/api"
).replace(/\/$/, "");

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const styles = {
  page: {
    width: "100%",
    height: "100%",
    minHeight: 0,
    overflowY: "auto",
    padding: "24px",
    background: "#08080b",
    color: "#d0cbd3",
    fontFamily: "Inter, sans-serif",
    fontSize: "13px",
    boxSizing: "border-box"
  },
  card: {
    background: "#0a090d",
    border: "1px solid #33202a",
    borderRadius: "10px",
    padding: "18px"
  },
  muted: {
    color: "#827b87",
    fontSize: "11px"
  },
  button: {
    background: "#241017",
    border: "1px solid #85364e",
    color: "#e99bad",
    padding: "9px 14px",
    borderRadius: "6px",
    cursor: "pointer",
    fontSize: "11px"
  },
  heading: {
    fontSize: "13px",
    fontWeight: 700,
    letterSpacing: "0.7px",
    color: "#d0cbd3"
  },
  select: {
    background: "#07070a",
    color: "#d0cbd3",
    border: "1px solid #633044",
    padding: "9px",
    borderRadius: "6px",
    fontSize: "11px"
  }
};

const severityColor = {
  CRITICAL: "#ff435d",
  HIGH: "#ff805d",
  MEDIUM: "#e8b65b",
  LOW: "#64c99b"
};

function getHeaders() {
  const token =
    sessionStorage.getItem("token") ||
    localStorage.getItem("token");

  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    "Content-Type": "application/json"
  };
}

async function fetchJSON(url) {
  const response = await fetch(url, {
    headers: getHeaders()
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message || `Request failed (${response.status})`
    );
  }

  return data;
}

function StatCard({ title, value, description, color }) {
  return (
    <div style={styles.card}>
      <div style={styles.muted}>{title}</div>

      <div
        style={{
          fontSize: "24px",
          fontWeight: 700,
          margin: "12px 0 7px",
          color
        }}
      >
        {value ?? 0}
      </div>

      <div style={styles.muted}>{description}</div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const color = severityColor[severity] || "#aaa";

  return (
    <span
      style={{
        display: "inline-block",
        color,
        background: `${color}18`,
        border: `1px solid ${color}55`,
        padding: "4px 9px",
        borderRadius: "5px",
        fontSize: "10px",
        fontWeight: 700,
        letterSpacing: "0.5px"
      }}
    >
      {severity || "UNKNOWN"}
    </span>
  );
}

export default function SecurityCommandCenter() {
  const [summary, setSummary] = useState(null);
  const [events, setEvents] = useState([]);
  const [severity, setSeverity] = useState("ALL");
  const [source, setSource] = useState("ALL");
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchSummary = useCallback(async () => {
    const data = await fetchJSON(`${API_URL}/security/summary`);
    setSummary(data.summary || null);
  }, []);

  const fetchEvents = useCallback(async () => {
    const params = new URLSearchParams({
      page: String(page),
      limit: "20"
    });

    if (severity !== "ALL") {
      params.set("severity", severity);
    }

    if (source !== "ALL") {
      params.set("source", source);
    }

    const data = await fetchJSON(
      `${API_URL}/security/events?${params.toString()}`
    );

    setEvents(data.events || []);
    setPagination(data.pagination || {});
  }, [page, severity, source]);

  const refreshDashboard = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      await Promise.all([
        fetchSummary(),
        fetchEvents()
      ]);
    } catch (err) {
      setError(
        err.message || "Security dashboard failed to load."
      );
    } finally {
      setLoading(false);
    }
  }, [fetchSummary, fetchEvents]);

  useEffect(() => {
    refreshDashboard();
  }, [refreshDashboard]);

  useEffect(() => {
    const interval = setInterval(() => {
      refreshDashboard();
    }, 15000);

    return () => clearInterval(interval);
  }, [refreshDashboard]);

  const severityCounts = summary?.severity || {};

  const cellStyle = {
    padding: "13px 10px",
    borderBottom: "1px solid #29202a",
    fontSize: "11px",
    verticalAlign: "top",
    color: "#d0cbd3"
  };

  return (
    <div style={styles.page}>
      {/* HEADER */}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "14px",
          marginBottom: "25px"
        }}
      >
        <div>
          <div
            style={{
              color: "#a34b65",
              fontSize: "10px",
              letterSpacing: "2px",
              fontWeight: 700
            }}
          >
            SECUREX // PLAYCIPHER
          </div>

          <h1
            style={{
              fontSize: "21px",
              fontWeight: 600,
              margin: "8px 0",
              color: "#e1dbe3"
            }}
          >
            Security Command Center
          </h1>

          <p style={styles.muted}>
            Intelligent threat monitoring and security event analysis
          </p>
        </div>

        <button
          style={styles.button}
          onClick={refreshDashboard}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "↻ Refresh"}
        </button>
      </div>

      {/* ERROR */}

      {error && (
        <div
          style={{
            ...styles.card,
            borderColor: "#85364e",
            color: "#ff8293",
            marginBottom: "20px"
          }}
        >
          {error}
        </div>
      )}

      {/* SECURITY OVERVIEW */}

      <h3 style={{ ...styles.heading, marginBottom: "13px" }}>
        SECURITY OVERVIEW
      </h3>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "13px",
          marginBottom: "25px"
        }}
      >
        <StatCard
          title="TOTAL SECURITY EVENTS"
          value={summary?.totalEvents}
          description="All recorded events"
          color="#e1dbe3"
        />

        <StatCard
          title="LAST 24 HOURS"
          value={summary?.eventsLast24Hours}
          description="Recently detected events"
          color="#e8b65b"
        />

        <StatCard
          title="HIGH SEVERITY"
          value={
            (severityCounts.HIGH || 0) +
            (severityCounts.CRITICAL || 0)
          }
          description="High and critical events"
          color="#ff657b"
        />

        <StatCard
          title="CRITICAL THREATS"
          value={severityCounts.CRITICAL}
          description="Critical recorded events"
          color="#ff435d"
        />
      </div>

      {/* THREAT DISTRIBUTION */}

      <div style={{ ...styles.card, marginBottom: "25px" }}>
        <h3 style={{ ...styles.heading, marginTop: 0 }}>
          THREAT SEVERITY DISTRIBUTION
        </h3>

        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => {
          const count = severityCounts[level] || 0;
          const total = summary?.totalEvents || 0;

          const percentage = total
            ? Math.round((count / total) * 100)
            : 0;

          return (
            <div key={level} style={{ marginTop: "17px" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "7px",
                  fontSize: "11px"
                }}
              >
                <span>{level}</span>
                <span>
                  {count} events ({percentage}%)
                </span>
              </div>

              <div
                style={{
                  height: "7px",
                  background: "#25232a",
                  borderRadius: "10px",
                  overflow: "hidden"
                }}
              >
                <div
                  style={{
                    width: `${percentage}%`,
                    height: "100%",
                    background: severityColor[level],
                    borderRadius: "10px",
                    transition: "width 300ms ease"
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* SECURITY EVENT HISTORY */}

      <div style={{ ...styles.card, marginBottom: "20px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "12px"
          }}
        >
          <h3 style={{ ...styles.heading, margin: 0 }}>
            SECURITY EVENT HISTORY
          </h3>

          <span style={styles.muted}>
            {pagination.total || 0} recorded events
          </span>
        </div>

        {/* FILTERS */}

        <div
          style={{
            display: "flex",
            gap: "9px",
            flexWrap: "wrap",
            margin: "18px 0"
          }}
        >
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            style={styles.select}
          >
            {SEVERITIES.map((item) => (
              <option key={item} value={item}>
                {item === "ALL" ? "All Severities" : item}
              </option>
            ))}
          </select>

          <select
            value={source}
            onChange={(e) => {
              setSource(e.target.value);
              setPage(1);
            }}
            style={styles.select}
          >
            <option value="ALL">All Sources</option>
            <option value="HTTP">HTTP</option>
            <option value="AUTH">Authentication</option>
            <option value="SOCKET">Socket.IO</option>
            <option value="SYSTEM">System</option>
          </select>
        </div>

        {/* LOADING STATE */}

        {loading && events.length === 0 ? (
          <p style={styles.muted}>
            Loading security events...
          </p>
        ) : events.length === 0 ? (

          /* EMPTY STATE — ONE SHIELD ICON */

          <div
            style={{
              textAlign: "center",
              padding: "35px 10px",
              color: "#827b87"
            }}
          >
            <div
              style={{
                fontSize: "25px",
                marginBottom: "10px",
                color: "#e58ba3",
                filter: "drop-shadow(0 0 7px #ff526f88)"
              }}
            >
              <i className="bi bi-shield-lock-fill"></i>
            </div>

            No matching security events found.
          </div>
        ) : (

          /* EVENT TABLE */

          <div style={{ width: "100%", overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                background: "#0a090d",
                color: "#d0cbd3"
              }}
            >
              <thead>
                <tr style={{ color: "#827b87", fontSize: "10px" }}>
                  {[
                    "EVENT",
                    "SEVERITY",
                    "SOURCE",
                    "USER",
                    "IP ADDRESS",
                    "TIME"
                  ].map((heading) => (
                    <th
                      key={heading}
                      style={{
                        padding: "13px 10px",
                        borderBottom: "1px solid #33202a",
                        fontWeight: 600,
                        textAlign: "left",
                        whiteSpace: "nowrap"
                      }}
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {events.map((event) => (
                  <tr key={event._id}>
                    <td style={cellStyle}>
                      <div
                        style={{
                          fontWeight: 600,
                          fontSize: "11px"
                        }}
                      >
                        {event.type}
                      </div>

                      <div style={styles.muted}>
                        {event.description}
                      </div>
                    </td>

                    <td style={cellStyle}>
                      <SeverityBadge severity={event.severity} />
                    </td>

                    <td style={cellStyle}>
                      {event.source}
                    </td>

                    <td style={cellStyle}>
                      {event.userId?.name || "Unknown"}
                    </td>

                    <td style={cellStyle}>
                      {event.ipAddress || "Unknown"}
                    </td>

                    <td style={cellStyle}>
                      {event.detectedAt
                        ? new Date(event.detectedAt).toLocaleString()
                        : "Unknown"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* PAGINATION */}

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "20px",
            gap: "10px",
            flexWrap: "wrap"
          }}
        >
          <span style={styles.muted}>
            Page {pagination.page || 1} of {pagination.totalPages || 1}
          </span>

          <div style={{ display: "flex", gap: "8px" }}>
            <button
              style={styles.button}
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </button>

            <button
              style={styles.button}
              disabled={
                page >= (pagination.totalPages || 1) || loading
              }
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* LATEST EVENT */}

      {summary?.latestEvent && (
        <div style={styles.card}>
          <h3 style={{ ...styles.heading, marginTop: 0 }}>
            LATEST DETECTED EVENT
          </h3>

          <div style={{ marginTop: "12px" }}>
            <SeverityBadge
              severity={summary.latestEvent.severity}
            />

            <strong
              style={{
                marginLeft: "10px",
                fontSize: "12px"
              }}
            >
              {summary.latestEvent.type}
            </strong>

            <p style={styles.muted}>
              Source: {summary.latestEvent.source}
            </p>

            <p style={styles.muted}>
              {summary.latestEvent.detectedAt
                ? new Date(
                    summary.latestEvent.detectedAt
                  ).toLocaleString()
                : "Unknown"}
            </p>
          </div>
        </div>
      )}

      {/* ENCRYPTION VERIFICATION — NEW, SEPARATE PANEL */}

      <EncryptionVerificationPanel />

      {/* FOOTER */}

      <div
        style={{
          marginTop: "20px",
          color: "#514b56",
          fontSize: "9px",
          letterSpacing: "1px"
        }}
      >
        SECUREX PLAYCIPHER · SECURITY MONITORING
      </div>
    </div>
  );
}
