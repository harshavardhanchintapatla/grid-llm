const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Mock data - replace with actual API calls
const mockAlerts = [
  {
    id: 1,
    timestamp: new Date().toISOString(),
    attackerOutstation: '192.168.1.100',
    victimOutstation: '192.168.1.50',
    functionCode: '0x05',
    severity: 'high',
    status: 'active',
    llmReasoning: 'Detected unauthorized OPERATE command from non-master device. This indicates a potential man-in-the-middle attack attempting to manipulate control points.',
    mitigation: 'SDN flow rule applied: Blocked traffic from 192.168.1.100 to 192.168.1.50. Isolated attacker from network segment.',
    packetTrace: {
      srcIP: '192.168.1.100',
      dstIP: '192.168.1.50',
      protocol: 'DNP3',
      functionCode: '0x05',
      dataPoints: ['AI-10', 'BO-23'],
      payload: '0x0564010500010017...'
    }
  }
];

// API endpoints
app.get('/api/alerts', (req, res) => {
  res.json(mockAlerts);
});

app.get('/api/alerts/:id', (req, res) => {
  const alert = mockAlerts.find(a => a.id === parseInt(req.params.id));
  if (alert) {
    res.json(alert);
  } else {
    res.status(404).json({ error: 'Alert not found' });
  }
});

app.get('/api/stats', (req, res) => {
  res.json({
    totalAlerts: 47,
    activeThreats: 3,
    mitigatedThreats: 44,
    networkHealth: 87
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
