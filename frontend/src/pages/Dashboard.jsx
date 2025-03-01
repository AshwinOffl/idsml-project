import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePredictionContext } from "../context/PredictionContext";
import { Line, Bar, Pie, Doughnut } from "react-chartjs-2";
import { io } from "socket.io-client";
import Sidebar from "../components/Sidebar";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  LineElement,
  PointElement,
  ArcElement,
  Filler,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  LineElement,
  PointElement,
  ArcElement,
  Filler
);

const socket = io("http://localhost:5000");

const Dashboard = () => {
  const navigate = useNavigate();
  const {
    notifications,
    totalAlerts,
    totalIntrusions,
    intrusionCountsByPrediction,
  } = usePredictionContext();

  const [packets, setPackets] = useState([]);
  const [protocolCounts, setProtocolCounts] = useState({});
  const [trafficOverTime, setTrafficOverTime] = useState([]);

  useEffect(() => {
    socket.on("real-time-packet", (packet) => {
      setPackets((prevPackets) => [packet, ...prevPackets.slice(0, 9)]);
      setProtocolCounts((prevCounts) => ({
        ...prevCounts,
        [packet.protocol]: (prevCounts[packet.protocol] || 0) + 1,
      }));

      // Update traffic over time
      setTrafficOverTime((prevTraffic) => [
        ...prevTraffic,
        { timestamp: packet.timestamp, length: packet.length },
      ]);
    });

    return () => socket.off("real-time-packet");
  }, []);

  const protocolData = {
    labels: Object.keys(protocolCounts),
    datasets: [
      {
        label: "Protocol Usage",
        data: Object.values(protocolCounts),
        backgroundColor: ["#36A2EB", "#FF6384", "#FFCE56"],
      },
    ],
  };

  const trafficData = {
    labels: trafficOverTime.map((traffic) => traffic.timestamp),
    datasets: [
      {
        label: "Traffic Over Time",
        data: trafficOverTime.map((traffic) => traffic.length),
        borderColor: "#36A2EB",
        fill: false,
      },
    ],
  };

  const alertData = {
    labels: Object.keys(intrusionCountsByPrediction),
    datasets: [
      {
        label: "Alerts by Type",
        data: Object.values(intrusionCountsByPrediction),
        backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0"],
      },
    ],
  };

  return (
    <div className="flex h-screen">
      <Sidebar />
      <div className="flex-1 p-8 ml-64 bg-gray-100 overflow-auto">
        <h1 className="text-3xl font-bold mb-6">Dashboard Analytics</h1>

        <div className="overflow-auto bg-white shadow-md rounded-lg p-4 mb-6">
          <h3 className="text-xl font-semibold mb-4">Live Network Traffic</h3>
          <table className="w-full table-auto">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Client IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Packet Length</th>
                <th>Prediction</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((packet, idx) => (
                <tr key={idx}>
                  <td>{packet.timestamp}</td>
                  <td>{packet.src_ip}</td>
                  <td>{packet.dst_ip}</td>
                  <td>{packet.protocol}</td>
                  <td>{packet.length}</td>
                  <td className={packet.prediction !== "Normal" ? "text-red-500 font-bold" : "text-green-600"}>{packet.prediction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white shadow-md rounded-lg p-4">
            <h3 className="text-xl font-semibold mb-4">Intrusion Prediction Distribution</h3>
            <Pie data={{
              labels: Object.keys(intrusionCountsByPrediction),
              datasets: [{
                data: Object.values(intrusionCountsByPrediction),
                backgroundColor: ["#4BC0C0", "#FF6384", "#FF9F40", "#36A2EB"],
              }],
            }} />
          </div>
          
          <div className="bg-white shadow-md rounded-lg p-4">
            <h3 className="text-xl font-semibold mb-4">Protocol Usage</h3>
            <Doughnut data={protocolData} />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
          <div className="bg-white shadow-md rounded-lg p-4">
            <h3 className="text-xl font-semibold mb-4">Traffic Over Time</h3>
            <Line data={trafficData} />
          </div>

          <div className="bg-white shadow-md rounded-lg p-4">
            <h3 className="text-xl font-semibold mb-4">Alerts by Type</h3>
            <Bar data={alertData} />
          </div>
        </div>

        <div className="bg-white shadow-md rounded-lg p-4 mt-6">
          <h3 className="text-xl font-semibold mb-4">Recent Alerts</h3>
          <table className="w-full table-auto">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Client IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Packet Length</th>
                <th>Prediction</th>
              </tr>
            </thead>
            <tbody>
              {notifications.slice(0, 10).map((notification, idx) => (
                <tr key={idx}>
                  <td>{notification.timestamp}</td>
                  <td>{notification.src_ip}</td>
                  <td>{notification.dst_ip}</td>
                  <td>{notification.protocol}</td>
                  <td>{notification.length}</td>
                  <td className={notification.prediction !== "Normal" ? "text-red-500 font-bold" : "text-green-600"}>{notification.prediction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;