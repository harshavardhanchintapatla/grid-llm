import React, { useState, useEffect } from 'react';
import './App.css';
import Dashboard from './components/Dashboard';
import axios from 'axios';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [alertsRes, statsRes] = await Promise.all([
        axios.get('/api/alerts'),
        axios.get('/api/stats')
      ]);
      setAlerts(alertsRes.data);
      setStats(statsRes.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading Dashboard...</div>;
  }

  return (
    <div className="App">
      <Dashboard alerts={alerts} stats={stats} />
    </div>
  );
}

export default App;
