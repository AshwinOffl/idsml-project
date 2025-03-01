import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

const RealTimeData = () => {
  // State to store the real-time data
  const [data, setData] = useState(null);

  useEffect(() => {
    // Connect to the Flask Socket.IO server
    const socket = io('http://localhost:5000', {
      transports: ['websocket'],
    });

    // Listen for 'real-time-data' events from the server
    socket.on('real-time-data', (newData) => {
      setData(newData); // Update state with the received data
    });

    // Cleanup on component unmount
    return () => {
      socket.disconnect();
    };
  }, []);

  // Render the data if available
  return (
    <div>
      <h1>Real-Time Data</h1>
      {data ? (
        <div>
          <p><strong>Timestamp:</strong> {data.timestamp}</p>
          <p><strong>Prediction:</strong> {data.prediction}</p>
          <p><strong>Client IP:</strong> {data.client_ip}</p> {/* Display client_ip */}
          <p><strong>Confidence:</strong> {data.confidence}</p>
        </div>
      ) : (
        <p>Waiting for real-time data...</p>
      )}
    </div>
  );
};

export default RealTimeData;
