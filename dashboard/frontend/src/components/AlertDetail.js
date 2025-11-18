import React from 'react';
import './AlertDetail.css';

const AlertDetail = ({ alert }) => {
  if (!alert) {
    return (
      <div className="alert-detail">
        <div className="no-alert">Select an alert to view details</div>
      </div>
    );
  }

  return (
    <div className="alert-detail">
      <div className="panel-header">
        <h2>Alert Analysis</h2>
        <span className={`status-badge ${alert.status}`}>{alert.status}</span>
      </div>

      <div className="detail-section">
        <h3>🤖 LLM Reasoning & Explainability</h3>
        <div className="reasoning-box">
          <p>{alert.llmReasoning}</p>
        </div>
      </div>

      <div className="detail-section">
        <h3>🛡️ Applied Mitigation</h3>
        <div className="mitigation-box">
          <p>{alert.mitigation}</p>
        </div>
      </div>

      <div className="detail-section">
        <h3>📦 Packet Trace</h3>
        <div className="packet-trace">
          <div className="trace-row">
            <span className="trace-label">Source IP:</span>
            <span className="trace-value">{alert.packetTrace.srcIP}</span>
          </div>
          <div className="trace-row">
            <span className="trace-label">Destination IP:</span>
            <span className="trace-value">{alert.packetTrace.dstIP}</span>
          </div>
          <div className="trace-row">
            <span className="trace-label">Protocol:</span>
            <span className="trace-value">{alert.packetTrace.protocol}</span>
          </div>
          <div className="trace-row">
            <span className="trace-label">Function Code:</span>
            <span className="trace-value code">{alert.packetTrace.functionCode}</span>
          </div>
          <div className="trace-row">
            <span className="trace-label">Data Points:</span>
            <span className="trace-value">{alert.packetTrace.dataPoints.join(', ')}</span>
          </div>
          <div className="trace-row full">
            <span className="trace-label">Payload:</span>
            <code className="payload">{alert.packetTrace.payload}</code>
          </div>
        </div>
      </div>

      <div className="detail-section">
        <h3>ℹ️ Alert Metadata</h3>
        <div className="metadata">
          <div className="meta-item">
            <span className="meta-label">Alert ID:</span>
            <span className="meta-value">#{alert.id}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Timestamp:</span>
            <span className="meta-value">{new Date(alert.timestamp).toLocaleString()}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Severity:</span>
            <span className={`meta-value severity-${alert.severity}`}>{alert.severity.toUpperCase()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertDetail;
