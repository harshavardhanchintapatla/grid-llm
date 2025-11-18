import React from 'react';
import './AlertList.css';

const AlertList = ({ alerts, selectedAlert, onSelectAlert }) => {
  const getSeverityClass = (severity) => {
    return `severity-${severity}`;
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  return (
    <div className="alert-list">
      <div className="panel-header">
        <h2>Security Alerts</h2>
        <span className="alert-count">{alerts.length}</span>
      </div>
      
      <div className="alert-items">
        {alerts.map(alert => (
          <div 
            key={alert.id}
            className={`alert-item ${selectedAlert?.id === alert.id ? 'selected' : ''} ${getSeverityClass(alert.severity)}`}
            onClick={() => onSelectAlert(alert)}
          >
            <div className="alert-item-header">
              <span className={`severity-badge ${alert.severity}`}>
                {alert.severity.toUpperCase()}
              </span>
              <span className="alert-time">{formatTime(alert.timestamp)}</span>
            </div>
            
            <div className="alert-item-content">
              <div className="alert-info">
                <span className="label">Function Code:</span>
                <span className="value code">{alert.functionCode}</span>
              </div>
              <div className="alert-info">
                <span className="label">Attacker:</span>
                <span className="value">{alert.attackerOutstation}</span>
              </div>
              <div className="alert-info">
                <span className="label">Target:</span>
                <span className="value">{alert.victimOutstation}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AlertList;
