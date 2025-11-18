import React from 'react';
import './StatsCards.css';

const StatsCards = ({ stats }) => {
  if (!stats) return null;

  return (
    <div className="stats-cards">
      <div className="stat-card">
        <div className="stat-icon total">📊</div>
        <div className="stat-content">
          <div className="stat-value">{stats.totalAlerts}</div>
          <div className="stat-label">Total Alerts</div>
        </div>
      </div>
      
      <div className="stat-card">
        <div className="stat-icon danger">⚠️</div>
        <div className="stat-content">
          <div className="stat-value">{stats.activeThreats}</div>
          <div className="stat-label">Active Threats</div>
        </div>
      </div>
      
      <div className="stat-card">
        <div className="stat-icon success">✓</div>
        <div className="stat-content">
          <div className="stat-value">{stats.mitigatedThreats}</div>
          <div className="stat-label">Mitigated</div>
        </div>
      </div>
      
      <div className="stat-card">
        <div className="stat-icon health">💚</div>
        <div className="stat-content">
          <div className="stat-value">{stats.networkHealth}%</div>
          <div className="stat-label">Network Health</div>
        </div>
      </div>
    </div>
  );
};

export default StatsCards;
