import React, { useEffect, useState } from "react";
import { io } from "socket.io-client";
import { Line, Bar, Doughnut } from "react-chartjs-2";
import { Chart, registerables } from "chart.js";

Chart.register(...registerables);

const Dashboard = () => {
  const [realTimeData, setRealTimeData] = useState([]);

  // Socket connection
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
    });

    return () => {
      socket.off("real-time-data");
    };
  }, []);

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
    <div className="p-6 bg-gray-100">
      <h1 className="text-2xl font-bold mb-6">Real-Time Data Dashboard</h1>

      {/* Grid layout for Tables */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Table 1: Raw Real-Time Data */}
        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">Raw Real-Time Data</h2>
          <table className="w-full border-collapse border">
            <thead>
              <tr>
                <th className="border p-2">Timestamp</th>
                <th className="border p-2">Prediction</th>
              </tr>
            </thead>
            <tbody>
              {realTimeData.slice(-5).map((item, index) => (
                <tr key={index}>
                  <td className="border p-2">{item.timestamp}</td>
                  <td className="border p-2">{item.prediction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Table 2: High Confidence */}
        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">High Confidence Predictions</h2>
          <p>Total: {highConfidenceCount}</p>
        </div>

        {/* Table 3: Low Confidence */}
        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">Low Confidence Predictions</h2>
          <p>Total: {lowConfidenceCount}</p>
        </div>

        {/* Table 4: Summary */}
        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">Summary Metrics</h2>
          <p>Normal Predictions: {normalCount}</p>
          <p>Attack Predictions: {attackCount}</p>
        </div>
      </div>

      {/* Grid layout for Charts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Chart 1: Line Chart for Trends */}
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

        {/* Chart 2: Bar Chart for Prediction Counts */}
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

        {/* Chart 3: Doughnut Chart for Confidence Levels */}
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
  );
};

export default Dashboard;
