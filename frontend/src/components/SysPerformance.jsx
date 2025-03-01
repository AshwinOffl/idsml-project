import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

const SysPerformance = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Initialize Socket.IO client to connect to the server
  const socket = io('http://localhost:5000'); // Ensure this matches your backend address
  
  // Handle new real-time alerts from the backend
  useEffect(() => {
    // Handle the socket connection for real-time alerts
    socket.on('real_time_alert', (alert) => {
      console.log('Received alert:', alert); // Log the alert to check if it's coming in
      setAlerts((prevAlerts) => {
        // Limit the alerts to the latest 3
        const updatedAlerts = [alert, ...prevAlerts];
        return updatedAlerts.slice(0, 3); // Keep only the latest 3 alerts
      });
      setLoading(false); // Stop loading once data starts arriving
    });

    // Clean up the socket connection when the component unmounts
    return () => {
      socket.off('real_time_alert');
    };
  }, [socket]);

  return (
    <div className="bg-white p-4 rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-4">System Performance & Alerts</h2>

      {/* Show loading spinner if data is being fetched */}
      {loading && <p>Loading real-time alerts...</p>}

      {/* Display active alerts */}
      <div className="space-y-4">
        {alerts.length === 0 ? (
          <p>No active alerts</p>
        ) : (
          alerts.map((alert, index) => (
            <div
              key={index}
              className={`p-3 border-l-4 ${alert.type === 'System Performance Alert' ? 'border-red-500 bg-red-50' : 'border-yellow-500 bg-yellow-50'}`}
            >
              <h3 className="text-xl font-semibold">{alert.type}</h3>
              <p className="text-sm text-gray-700">{alert.timestamp}</p>
              <p className="mt-2">{alert.message}</p>
              {alert.details && (
                <pre className="mt-2 text-sm text-gray-600">{JSON.stringify(alert.details, null, 2)}</pre>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default SysPerformance;
