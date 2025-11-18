# DNP3 Security Operations Dashboard

An operator-focused interface for visualizing DNP3 security events and SDN-LLM framework mitigation actions.

## Features

- **Real-time Alert Monitoring**: View security alerts with severity levels and timestamps
- **LLM Explainability**: See AI reasoning for threat detection and analysis
- **SDN Mitigation Display**: View applied network rules and isolation actions
- **Network Topology Visualization**: Interactive view of attacker, victim, and SDN controller
- **Packet-level Traces**: Detailed DNP3 packet information and metadata
- **Statistics Dashboard**: Overview of total alerts, active threats, and network health

## Tech Stack

- **Frontend**: React 18, Axios, Recharts
- **Backend**: Node.js, Express.js
- **Styling**: Custom CSS with modern gradients and animations

## Installation

### 1. Install all dependencies

```bash
cd dashboard
npm run install-all
```

This will install dependencies for both frontend and backend.

### 2. Configure Backend (Optional)

Edit `backend/.env` to change the port:

```
PORT=5000
```

### 3. Run the Application

From the `dashboard` directory:

```bash
npm run dev
```

This starts both:
- Backend API on http://localhost:5000
- Frontend on http://localhost:3000

Or run them separately:

```bash
# Terminal 1 - Backend
npm run server

# Terminal 2 - Frontend
npm run client
```

## API Integration

The dashboard fetches data from these endpoints:

- `GET /api/alerts` - List of security alerts
- `GET /api/alerts/:id` - Specific alert details
- `GET /api/stats` - Dashboard statistics

### Replace Mock Data

Edit `backend/server.js` to connect to your actual API:

```javascript
// Replace mockAlerts with your API call
app.get('/api/alerts', async (req, res) => {
  try {
    const response = await fetch('YOUR_API_URL/alerts');
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Data Format

Expected alert object structure:

```json
{
  "id": 1,
  "timestamp": "2025-11-17T10:30:00Z",
  "attackerOutstation": "192.168.1.100",
  "victimOutstation": "192.168.1.50",
  "functionCode": "0x05",
  "severity": "high",
  "status": "active",
  "llmReasoning": "AI explanation of the threat",
  "mitigation": "SDN action taken",
  "packetTrace": {
    "srcIP": "192.168.1.100",
    "dstIP": "192.168.1.50",
    "protocol": "DNP3",
    "functionCode": "0x05",
    "dataPoints": ["AI-10", "BO-23"],
    "payload": "0x0564010500010017..."
  }
}
```

## Customization

- **Colors**: Edit CSS files in `frontend/src/components/`
- **Refresh Rate**: Change interval in `App.js` (default: 5 seconds)
- **Layout**: Modify grid in `Dashboard.css`

## Production Build

```bash
cd frontend
npm run build
```

Serve the build folder with your preferred static server or integrate with backend.
