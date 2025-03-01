import React, { useEffect, useState, useRef } from "react";
import { io } from "socket.io-client";
import AdminSidebar from "../components/AdminSidebar";

const SystemPerformancePage = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");
  const alertEndRef = useRef(null);

  // Initialize Socket.IO client to connect to the server
  const socket = io("http://localhost:5000"); // Ensure this matches your backend address

  useEffect(() => {
    socket.on("real_time_alert", (alert) => {
      console.log("Received alert:", alert);
      setAlerts((prevAlerts) => {
        const updatedAlerts = [alert, ...prevAlerts];
        return updatedAlerts.slice(0, 10); // Limit to latest 10 alerts
      });
      setLoading(false);

      // Scroll to the newest alert
      alertEndRef.current?.scrollIntoView({ behavior: "smooth" });
    });

    return () => {
      socket.off("real_time_alert");
    };
  }, []);

  // Filter alerts based on selected type
  const filteredAlerts = alerts.filter((alert) => {
    if (filter === "All") return true;
    return alert.type === filter;
  });

  // Filter alerts by search term
  const searchedAlerts = filteredAlerts.filter((alert) =>
    alert.message.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex">
      <AdminSidebar />
      <div className="ml-20 flex-1 p-4">
        <h1 className="text-3xl font-bold mb-6">System Performance & Alerts</h1>

        {/* Filters and Search */}
        <div className="flex items-center justify-between mb-4">
          <select
            className="p-2 border rounded"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="All">All Alerts</option>
            <option value="System Performance Alert">System Performance Alert</option>
            <option value="Warning">Warning</option>
          </select>

          <input
            type="text"
            className="p-2 border rounded w-1/2"
            placeholder="Search alerts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <button
            className="p-2 bg-red-500 text-white rounded hover:bg-red-600"
            onClick={() => setAlerts([])}
          >
            Clear Alerts
          </button>
        </div>

        {/* Show loading spinner if data is being fetched */}
        {loading && <p className="text-gray-500">Loading real-time alerts...</p>}

        {/* Display active alerts */}
        <div className="space-y-4 max-h-[500px] overflow-auto">
          {searchedAlerts.length === 0 ? (
            <p className="text-gray-700">No matching alerts found</p>
          ) : (
            searchedAlerts.map((alert, index) => (
              <div
                key={index}
                className={`p-4 border-l-4 rounded ${
                  alert.type === "System Performance Alert"
                    ? "border-red-500 bg-red-50"
                    : "border-yellow-500 bg-yellow-50"
                }`}
              >
                <h3 className="text-xl font-semibold">{alert.type}</h3>
                <p className="text-sm text-gray-700">{alert.timestamp}</p>
                <p className="mt-2">{alert.message}</p>
                {alert.details && (
                  <pre className="mt-2 text-sm text-gray-600">
                    {JSON.stringify(alert.details, null, 2)}
                  </pre>
                )}
              </div>
            ))
          )}
          <div ref={alertEndRef} />
        </div>
      </div>
    </div>
  );
};

export default SystemPerformancePage;
