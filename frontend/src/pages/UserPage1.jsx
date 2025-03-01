import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import { Line, Bar, Doughnut } from "react-chartjs-2";
import { Chart, registerables } from "chart.js";
import Sidebar from "../components/Sidebar"; // Import Sidebar here
import Header from "../components/Header"; // Import Header here

Chart.register(...registerables);

const UserPage = () => {
  const [notifications, setNotifications] = useState([]);
  const [realTimeData, setRealTimeData] = useState([]);
  const [userInfo, setUserInfo] = useState({});
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  // Fetch user information (mocked here)
  const fetchUserInfo = async () => {
    try {
      const response = await fetch("http://localhost:5000/user-info", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      const data = await response.json();
      setUserInfo(data);
    } catch (error) {
      console.error("Failed to fetch user info:", error);
    }
  };

  // Socket connection for real-time updates
  useEffect(() => {
    const socket = io("http://localhost:5000");

    socket.on("real-time-data", (data) => {
      const fixedTimestamp = new Date(data.timestamp).getTime()
        ? new Date(data.timestamp)
        : new Date(Number(data.timestamp) * 1000);

      const newData = {
        ...data,
        timestamp: fixedTimestamp.toLocaleString(),
      };

      setRealTimeData((prevData) => [...prevData, newData]);
      setNotifications((prev) => [
        ...prev,
        {
          id: Date.now(),
          message: `Intrusion Detected, Attack Type: ${data.prediction}, Timestamp: ${fixedTimestamp.toLocaleString()}`,
          timestamp: fixedTimestamp.toLocaleString(),
        },
      ]);
    });

    fetchUserInfo();

    return () => {
      socket.off("real-time-data");
    };
  }, []);

  // Handle notification dismissal
  const dismissNotification = (id) => {
    setNotifications((prev) => prev.filter((notification) => notification.id !== id));
  };

  // Chart Data Preparation
  const timestamps = realTimeData.map((item) => item.timestamp);
  const predictions = realTimeData.map((item) =>
    item.prediction === "normal" ? 1 : 0
  );

  const highConfidenceCount = realTimeData.filter(
    (item) => item.confidence > 0.9
  ).length;

  const lowConfidenceCount = realTimeData.filter(
    (item) => item.confidence < 0.5
  ).length;

  const normalCount = realTimeData.filter(
    (item) => item.prediction === "normal"
  ).length;

  const attackCount = realTimeData.filter(
    (item) => item.prediction === "attack"
  ).length;

  return (
    <div className="flex">
      {/* Sidebar */}
      <Sidebar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />

      {/* Main Content */}
      <div className="flex-1 p-6 ml-64">
        {/* Header */}
        <Header />

        <div className="mt-20">
          <h2 className="text-3xl font-bold text-green-600 mb-4">
            Welcome, {userInfo.name || "Valued User"}!
          </h2>

          {/* Notifications */}
          <div>
            <h2 className="text-2xl font-semibold text-gray-700 mb-2">Notifications:</h2>
            <ul className="space-y-2">
              {notifications.length > 0 ? (
                notifications.map((notification) => (
                  <li
                    key={notification.id}
                    className="bg-red-100 p-4 rounded-md shadow-md flex justify-between items-center"
                  >
                    <div>
                      <p className="font-bold">{notification.message}</p>
                      <p className="text-gray-600">
                        <strong>Timestamp:</strong> {notification.timestamp}
                      </p>
                    </div>
                    <button
                      onClick={() => dismissNotification(notification.id)}
                      className="text-red-600 font-bold"
                    >
                      Dismiss
                    </button>
                  </li>
                ))
              ) : (
                <p className="text-gray-600">No notifications yet.</p>
              )}
            </ul>
          </div>

          {/* Real-Time Data and Charts */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            {/* Real-Time Data */}
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Real-Time Data</h2>
              {realTimeData.length > 0 ? (
                <div className="bg-blue-100 p-4 rounded-md">
                  <p className="text-gray-800">
                    <strong>Prediction:</strong> {realTimeData[realTimeData.length - 1].prediction}
                  </p>
                  <p className="text-gray-800">
                    <strong>Confidence:</strong> {(realTimeData[realTimeData.length - 1].confidence * 100).toFixed(2)}%
                  </p>
                  <p className="text-gray-800">
                    <strong>Timestamp:</strong> {realTimeData[realTimeData.length - 1].timestamp}
                  </p>
                </div>
              ) : (
                <p className="text-gray-600">Waiting for real-time data...</p>
              )}
            </div>

            {/* Charts */}
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Prediction Trends</h2>
              <Line
                data={{
                  labels: timestamps,
                  datasets: [
                    {
                      label: "Prediction Trend (1 = Normal, 0 = Attack)",
                      data: predictions,
                      borderColor: "blue",
                      backgroundColor: "rgba(0, 123, 255, 0.2)",
                      fill: true,
                    },
                  ],
                }}
              />
            </div>

            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Prediction Counts</h2>
              <Bar
                data={{
                  labels: ["Normal", "Attack"],
                  datasets: [
                    {
                      label: "Prediction Count",
                      data: [normalCount, attackCount],
                      backgroundColor: ["green", "red"],
                    },
                  ],
                }}
              />
            </div>

            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Confidence Distribution</h2>
              <Doughnut
                data={{
                  labels: ["High Confidence", "Low Confidence"],
                  datasets: [
                    {
                      label: "Confidence Levels",
                      data: [highConfidenceCount, lowConfidenceCount],
                      backgroundColor: ["#36A2EB", "#FFCE56"],
                    },
                  ],
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserPage;
