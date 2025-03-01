import { useEffect, useState } from "react";
import { usePredictionContext } from "../context/PredictionContext";
import { Line, Bar, Doughnut, Pie } from "react-chartjs-2";
import { Chart, registerables } from "chart.js";
import Sidebar from "../components/Sidebar";
import { Link, useNavigate } from "react-router-dom";

Chart.register(...registerables);

const UserPage = () => {
  const [userInfo, setUserInfo] = useState({});
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState("");
  const [localNotifications, setLocalNotifications] = useState([]);
  const [activityLogs, setActivityLogs] = useState([]);
  const [editProfile, setEditProfile] = useState(false);
  const [profileForm, setProfileForm] = useState({
    name: "",
    email: "",
    password: "",
  });

  const navigate = useNavigate();

  const {
    notifications,
    totalAlerts,
    totalIntrusions,
    intrusionCountsByPrediction,
  } = usePredictionContext();

  useEffect(() => {
    setLocalNotifications(notifications);
  }, [notifications]);

  const fetchUserInfo = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch("http://localhost:5000/user-info", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.status === 401) {
        navigate("/login");
        return;
      }

      const data = await response.json();
      setUserInfo(data);
      setProfileForm({ name: data.name, email: data.email, password: "" });
    } catch (error) {
      console.error("Failed to fetch user info:", error);
      navigate("/login");
    }
  };

  const fetchActivityLogs = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch("http://localhost:5000/user-activity-logs", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.status === 401) {
        navigate("/login");
        return;
      }

      const data = await response.json();
      setActivityLogs(data);
    } catch (error) {
      console.error("Failed to fetch activity logs:", error);
    }
  };

  useEffect(() => {
    fetchUserInfo();
    fetchActivityLogs();
  }, []);

  const handleCreateUser = async (newUserData) => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch("http://localhost:5000/admin/create_user", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newUserData),
      });

      const data = await response.json();

      if (response.status === 201) {
        setMessageType("success");
        setMessage(data.message);
      } else {
        setMessageType("error");
        setMessage(data.error);
      }
    } catch (error) {
      console.error("Error creating user:", error);
      setMessageType("error");
      setMessage("An error occurred while creating the user.");
    }
  };

  const dismissNotification = (id) => {
    setLocalNotifications((prev) => prev.filter((notif) => notif.id !== id));
  };

  const clearAllNotifications = () => {
    setLocalNotifications([]);
  };

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch("http://localhost:5000/update-profile", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(profileForm),
      });

      const data = await response.json();

      if (response.status === 200) {
        setMessageType("success");
        setMessage(data.message);
        setEditProfile(false);
        fetchUserInfo();
      } else {
        setMessageType("error");
        setMessage(data.error);
      }
    } catch (error) {
      console.error("Error updating profile:", error);
      setMessageType("error");
      setMessage("An error occurred while updating the profile.");
    }
  };

  const latestNotifications = localNotifications.slice(0, 3);

  const timestamps = localNotifications.map((item) => item.timestamp);
  const predictions = localNotifications.map((item) =>
    item.prediction === "normal" ? 1 : 0
  );

  const highConfidenceCount = localNotifications.filter(
    (item) => item.confidence > 0.9
  ).length;

  const lowConfidenceCount = localNotifications.filter(
    (item) => item.confidence < 0.5
  ).length;

  const normalCount = intrusionCountsByPrediction["normal"] || 0;
  const attackCount = intrusionCountsByPrediction["attack"] || 0;

  return (
    <div className="flex">
      <Sidebar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />

      <div className="flex-1 p-6 ml-64">
        <div className="mt-20">
          <h2 className="text-3xl font-bold text-green-600 mb-4">
            Welcome, {userInfo.name || "Valued User"}!
          </h2>

          {message && (
            <div
              className={`p-4 rounded-md mb-4 ${
                messageType === "success" ? "bg-green-100" : "bg-red-100"
              }`}
            >
              <p
                className={`font-bold ${
                  messageType === "success" ? "text-green-600" : "text-red-600"
                }`}
              >
                {message}
              </p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* User Profile Section */}
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">User Profile</h2>
              {editProfile ? (
                <form onSubmit={handleProfileUpdate}>
                  <div className="mb-4">
                    <label className="block text-gray-700">Name</label>
                    <input
                      type="text"
                      value={profileForm.name}
                      onChange={(e) =>
                        setProfileForm({ ...profileForm, name: e.target.value })
                      }
                      className="w-full p-2 border rounded"
                    />
                  </div>
                  <div className="mb-4">
                    <label className="block text-gray-700">Email</label>
                    <input
                      type="email"
                      value={profileForm.email}
                      onChange={(e) =>
                        setProfileForm({ ...profileForm, email: e.target.value })
                      }
                      className="w-full p-2 border rounded"
                    />
                  </div>
                  <div className="mb-4">
                    <label className="block text-gray-700">Password</label>
                    <input
                      type="password"
                      value={profileForm.password}
                      onChange={(e) =>
                        setProfileForm({ ...profileForm, password: e.target.value })
                      }
                      className="w-full p-2 border rounded"
                    />
                  </div>
                  <button
                    type="submit"
                    className="bg-blue-500 text-white p-2 rounded"
                  >
                    Save Changes
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditProfile(false)}
                    className="bg-gray-500 text-white p-2 rounded ml-2"
                  >
                    Cancel
                  </button>
                </form>
              ) : (
                <div>
                  <p className="text-gray-700">
                    <strong>Name:</strong> {userInfo.name}
                  </p>
                  <p className="text-gray-700">
                    <strong>Email:</strong> {userInfo.email}
                  </p>
                  <button
                    onClick={() => setEditProfile(true)}
                    className="bg-blue-500 text-white p-2 rounded mt-2"
                  >
                    Edit Profile
                  </button>
                </div>
              )}
            </div>

            {/* Notifications Section */}
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Notifications</h2>
              <ul className="space-y-2">
                {latestNotifications.length > 0 ? (
                  latestNotifications.map((notification) => (
                    <li
                      key={notification.id}
                      className="bg-red-100 p-4 rounded-md shadow-md flex justify-between items-center"
                    >
                      <div>
                        <p className="font-bold">Intrusion Detected</p>
                        <p className="font-bold">
                          Attack Type: {notification.prediction}
                        </p>
                        <p className="text-gray-600">
                          <strong>Client IP:</strong> {notification.client_ip}
                        </p>
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
              <div className="flex gap-4 mt-4">
                <Link to="/notifications">
                  <button className="text-blue-600 font-bold">
                    See All Notifications
                  </button>
                </Link>
                <button
                  onClick={clearAllNotifications}
                  className="text-red-600 font-bold"
                >
                  Clear All Notifications
                </button>
              </div>
            </div>
          </div>

          {/* Activity Logs Section */}
          <div className="bg-white p-4 rounded shadow mt-6">
            <h2 className="text-lg font-semibold mb-2">Activity Logs</h2>
            <table className="w-full table-auto">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Activity</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {activityLogs.map((log, idx) => (
                  <tr key={idx}>
                    <td>{log.timestamp}</td>
                    <td>{log.activity}</td>
                    <td>{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Real-Time Data and Charts Section */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            {/* Real-Time Data */}
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-lg font-semibold mb-2">Real-Time Data</h2>
              {localNotifications.length > 0 ? (
                <div className="bg-blue-100 p-4 rounded-md">
                  <p className="text-gray-800">
                    <strong>Prediction:</strong>{" "}
                    {localNotifications[localNotifications.length - 1].prediction}
                  </p>
                  <p className="text-gray-800">
                    <strong>Confidence:</strong>{" "}
                    {localNotifications[localNotifications.length - 1].confidence}%
                  </p>
                  <p className="text-gray-800">
                    <strong>Timestamp:</strong>{" "}
                    {localNotifications[localNotifications.length - 1].timestamp}
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
              <h2 className="text-lg font-semibold mb-2">
                Confidence Distribution
              </h2>
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