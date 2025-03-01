import React, { createContext, useState, useContext, useEffect } from "react";
import { io } from "socket.io-client";

// Create a Context
const PredictionContext = createContext();

// Custom hook to use PredictionContext
export const usePredictionContext = () => useContext(PredictionContext);

// PredictionProvider component
export const PredictionProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [totalIntrusions, setTotalIntrusions] = useState(0);
  const [intrusionCountsByPrediction, setIntrusionCountsByPrediction] = useState({});
  const [packets, setPackets] = useState([]);

  useEffect(() => {
    const socket = io("http://localhost:5000", {
      transports: ["websocket", "polling"],
    });

    socket.on("connect", () => {
      console.log("Connected to WebSocket server");
    });

    // Listen to real network packets instead of simulated data
    socket.on("real-time-packet", (packet) => {
      setPackets((prevPackets) => [packet, ...prevPackets.slice(0, 9)]);

      const newNotification = {
        id: Date.now(),
        prediction: packet.prediction,
        timestamp: packet.timestamp,
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        protocol: packet.protocol,
        length: packet.length,
      };

      setNotifications((prev) => [...prev, newNotification]);

      // Update alert counters
      setTotalAlerts((prev) => prev + 1);
      if (packet.prediction.toLowerCase() !== "normal") {
        setTotalIntrusions((prev) => prev + 1);
      }

      setIntrusionCountsByPrediction((prevCounts) => ({
        ...prevCounts,
        [packet.prediction]: (prevCounts[packet.prediction] || 0) + 1,
      }));
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from WebSocket server");
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return (
    <PredictionContext.Provider
      value={{
        notifications,
        setNotifications,
        totalAlerts,
        totalIntrusions,
        intrusionCountsByPrediction,
        packets,
      }}
    >
      {children}
    </PredictionContext.Provider>
  );
};
