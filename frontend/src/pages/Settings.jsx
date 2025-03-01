import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Sidebar from "../components/Sidebar"; // Import Sidebar component

const Settings = () => {
  const [userInfo, setUserInfo] = useState(null);
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [notification, setNotification] = useState("");
  const navigate = useNavigate();

  // Fetch user information on page load
  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await axios.get("http://localhost:5000/user-info", {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        });
        setUserInfo(response.data.user_info);
      } catch (error) {
        console.error("Failed to fetch user info", error);
        navigate("/login"); // Redirect to login if not authenticated
      }
    };
    fetchUserInfo();
  }, [navigate]);

  // Handle password update
  const handlePasswordUpdate = async (e) => {
    e.preventDefault();
    if (!oldPassword || !newPassword) {
      setNotification("Please fill in both the old and new password fields.");
      return;
    }

    try {
      const response = await axios.post(
        "http://localhost:5000/update-password",
        { old_password: oldPassword, new_password: newPassword },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );

      if (response.status === 200) {
        setNotification("Password updated successfully.");
      } else {
        setNotification(response.data.error || "Failed to update password. Please try again.");
      }
    } catch (error) {
      console.error("Error updating password:", error);
      setNotification("Failed to update password. Please try again.");
    }
  };

  // Handle notifications
  const handleNotificationClose = () => {
    setNotification("");
  };

  if (!userInfo) return <div>Loading...</div>;

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <div className="flex-1 p-4 ml-64">
        <h2 className="text-2xl font-bold mb-4">User Settings</h2>
        {notification && (
          <div className="bg-red-100 text-red-600 p-4 rounded mb-4">
            <p>{notification}</p>
            <button
              onClick={handleNotificationClose}
              className="text-red-800 underline"
            >
              Close
            </button>
          </div>
        )}
        <div className="bg-white shadow-md rounded p-4">
          <h3 className="text-xl font-bold mb-4">User Info</h3>
          <p><strong>User ID:</strong> {userInfo.user_id}</p>
          <p><strong>Role:</strong> {userInfo.role}</p>
        </div>

        <div className="bg-white shadow-md rounded p-4 mt-6">
          <h3 className="text-xl font-bold mb-4">Update Password</h3>
          <form onSubmit={handlePasswordUpdate}>
            <div className="mb-4">
              <label className="block text-gray-700">Old Password</label>
              <input
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                required
                className="w-full border rounded p-2"
              />
            </div>
            <div className="mb-4">
              <label className="block text-gray-700">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="w-full border rounded p-2"
              />
            </div>
            <button type="submit" className="bg-blue-500 text-white py-2 px-4 rounded">
              Update Password
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Settings;
