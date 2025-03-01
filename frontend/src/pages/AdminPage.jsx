import React, { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import SysPerformance from "../components/SysPerformance"; // Import the SysPerformance component
import AdminSidebar from "../components/AdminSidebar"; // Import AdminSidebar component

const AdminPage = () => {
  const [users, setUsers] = useState([]);
  const [loginHistory, setLoginHistory] = useState([]);
  const [newUser, setNewUser] = useState({ user_id: "", password: "", role: "user" });

  useEffect(() => {
    fetchUsers();
    fetchLoginHistory();
  }, []);

  // Fetch all users
  const fetchUsers = async () => {
    try {
      const response = await axios.get("http://localhost:5000/admin/users", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      setUsers(response.data.users);
    } catch (error) {
      console.error("Error fetching users:", error);
    }
  };

  // Fetch login history
  const fetchLoginHistory = async () => {
    try {
      const response = await axios.get("http://localhost:5000/admin/login_history", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      setLoginHistory(response.data.login_history);
    } catch (error) {
      console.error("Error fetching login history:", error);
    }
  };

  // Create a new user
  const handleCreateUser = async () => {
    try {
      await axios.post("http://localhost:5000/admin/create_user", newUser, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      fetchUsers();
      setNewUser({ user_id: "", password: "", role: "user" });
      toast.success("User created successfully!");
    } catch (error) {
      if (error.response?.data?.error === "User already exists") {
        toast.error("This user ID already exists. Please choose a different one.");
      } else {
        toast.error(
          error.response?.data?.error || "Failed to create user. Please try again."
        );
      }
    }
  };

  // Update user role
  const handleUpdateRole = async (userId, newRole) => {
    try {
      await axios.post(
        "http://localhost:5000/admin/update_user_role",
        { user_id: userId, role: newRole },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      fetchUsers();
      toast.success("User role updated successfully!");
    } catch (error) {
      toast.error(
        error.response?.data?.error || "Failed to update user role. Please try again."
      );
    }
  };

  // Delete user
  const handleDeleteUser = async (userId) => {
    try {
      await axios.post(
        "http://localhost:5000/admin/delete_user",
        { user_id: userId },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      fetchUsers();
      toast.success("User deleted successfully!");
    } catch (error) {
      toast.error(
        error.response?.data?.error || "Failed to delete user. Please try again."
      );
    }
  };

  return (
    <div className="ml-32 h-screen flex">
      {/* Sidebar */}
      <AdminSidebar />

      {/* Main Content */}
      <div className="flex-1 p-4">
        <h1 className="text-2xl font-bold mb-4">Admin Dashboard</h1>

        {/* SysPerformance Section */}
        <SysPerformance />

        {/* Create New User Section */}
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-2">Create New User</h2>
          <input
            type="text"
            placeholder="User ID"
            value={newUser.user_id}
            onChange={(e) => setNewUser({ ...newUser, user_id: e.target.value })}
            className="border p-2 mr-2"
          />
          <input
            type="password"
            placeholder="Password"
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            className="border p-2 mr-2"
          />
          <select
            value={newUser.role}
            onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
            className="border p-2 mr-2"
          >
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
          <button
            onClick={handleCreateUser}
            className="bg-blue-500 text-white px-4 py-2 rounded"
          >
            Create User
          </button>
        </div>

        {/* All Users Table */}
        <div>
          <h2 className="text-xl font-semibold mb-2">All Users</h2>
          <table className="min-w-full border">
            <thead>
              <tr>
                <th className="border px-4 py-2">User ID</th>
                <th className="border px-4 py-2">Role</th>
                <th className="border px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.user_id}>
                  <td className="border px-4 py-2">{user.user_id}</td>
                  <td className="border px-4 py-2">{user.role}</td>
                  <td className="border px-4 py-2">
                    <button
                      onClick={() =>
                        handleUpdateRole(
                          user.user_id,
                          user.role === "admin" ? "user" : "admin"
                        )
                      }
                      className="bg-yellow-500 text-white px-4 py-2 rounded mr-2"
                    >
                      {user.role === "admin" ? "Demote to User" : "Promote to Admin"}
                    </button>
                    <button
                      onClick={() => handleDeleteUser(user.user_id)}
                      className="bg-red-500 text-white px-4 py-2 rounded"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Login History Section */}
        <div className="mt-8">
          <h2 className="text-xl font-semibold mb-2">Login History</h2>
          <table className="min-w-full border">
            <thead>
              <tr>
                <th className="border px-4 py-2">User ID</th>
                <th className="border px-4 py-2">Timestamp</th>
                <th className="border px-4 py-2">Client IP</th>
                <th className="border px-4 py-2">User Agent</th>
              </tr>
            </thead>
            <tbody>
              {loginHistory.map((entry, index) => (
                <tr key={index}>
                  <td className="border px-4 py-2">{entry.user_id}</td>
                  <td className="border px-4 py-2">{entry.timestamp}</td>
                  <td className="border px-4 py-2">{entry.client_ip}</td>
                  <td className="border px-4 py-2">{entry.user_agent}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AdminPage;
