import React from 'react';
import './NetworkTopology.css';

const NetworkTopology = ({ alert }) => {
  if (!alert) return null;

  return (
    <div className="network-topology">
      <div className="panel-header">
        <h2>Network Topology</h2>
      </div>

      <div className="topology-view">
        <div className="topology-node sdn-controller">
          <div className="node-icon">🎛️</div>
          <div className="node-label">SDN Controller</div>
          <div className="node-status active">Active</div>
        </div>

        <div className="topology-connection blocked"></div>

        <div className="topology-row">
          <div className="topology-node attacker">
            <div className="node-icon">⚠️</div>
            <div className="node-label">Attacker</div>
            <div className="node-ip">{alert.attackerOutstation}</div>
            <div className="node-status blocked">Blocked</div>
          </div>

          <div className="topology-node victim">
            <div className="node-icon">🏭</div>
            <div className="node-label">Victim Outstation</div>
            <div className="node-ip">{alert.victimOutstation}</div>
            <div className="node-status protected">Protected</div>
          </div>
        </div>

        <div className="attack-indicator">
          <div className="attack-arrow">
            <span>❌</span>
            <div className="arrow-label">Blocked Attack</div>
          </div>
        </div>
      </div>

      <div className="topology-legend">
        <h3>Legend</h3>
        <div className="legend-items">
          <div className="legend-item">
            <span className="legend-color active"></span>
            <span>Active/Protected</span>
          </div>
          <div className="legend-item">
            <span className="legend-color blocked"></span>
            <span>Blocked/Isolated</span>
          </div>
          <div className="legend-item">
            <span className="legend-color warning"></span>
            <span>Under Attack</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkTopology;
