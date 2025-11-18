import React, { useState } from 'react';
import './Dashboard.css';
import Header from './Header';
import StatsCards from './StatsCards';
import AlertList from './AlertList';
import AlertDetail from './AlertDetail';
import NetworkTopology from './NetworkTopology';

const Dashboard = ({ alerts, stats }) => {
  const [selectedAlert, setSelectedAlert] = useState(alerts[0] || null);

  return (
    <div className="dashboard">
      <Header />
      
      <div className="dashboard-content">
        <StatsCards stats={stats} />
        
        <div className="main-grid">
          <div className="left-panel">
            <AlertList 
              alerts={alerts} 
              selectedAlert={selectedAlert}
              onSelectAlert={setSelectedAlert}
            />
          </div>
          
          <div className="center-panel">
            <AlertDetail alert={selectedAlert} />
          </div>
          
          <div className="right-panel">
            <NetworkTopology alert={selectedAlert} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
