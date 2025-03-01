// src/pages/AllUsersPage.jsx

import React, { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import AdminSidebar from "../components/AdminSidebar"; // Import AdminSidebar component

const AllUsersPage = () => {
  const [users, setUsers] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [sortConfig, setSortConfig] = useState({ key: null, direction: null });

  useEffect(() => {
    fetchUsers();
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

  // Suspend user
  const handleSuspendUser = async (userId) => {
    try {
      await axios.post(
        "http://localhost:5000/admin/suspend_user",
        { user_id: userId },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      fetchUsers();
      toast.success("User suspended successfully!");
    } catch (error) {
      toast.error(
        error.response?.data?.error || "Failed to suspend user. Please try again."
      );
    }
  };

  // Unsuspend user
  const handleUnsuspendUser = async (userId) => {
    try {
      await axios.post(
        "http://localhost:5000/admin/unsuspend_user",
        { user_id: userId },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      fetchUsers();
      toast.success("User unsuspended successfully!");
    } catch (error) {
      toast.error(
        error.response?.data?.error || "Failed to unsuspend user. Please try again."
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

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value.toLowerCase());
  };

  // Handle sorting
  const handleSort = (key) => {
    let direction = "asc";
    if (sortConfig.key === key && sortConfig.direction === "asc") {
      direction = "desc";
    }
    setSortConfig({ key, direction });

    const sortedData = [...users].sort((a, b) => {
      if (a[key] < b[key]) return direction === "asc" ? -1 : 1;
      if (a[key] > b[key]) return direction === "asc" ? 1 : -1;
      return 0;
    });
    setUsers(sortedData);
  };

  // Filter users based on search term
  const filteredUsers = users.filter(
    (user) =>
      user.user_id.toLowerCase().includes(searchTerm) ||
      user.role.toLowerCase().includes(searchTerm)
  );

  return (
    <div className="flex">
      {/* Sidebar */}
      <AdminSidebar /> {/* Sidebar on the left side */}

      {/* Main Content */}
      <div className="ml-20 flex-1 p-6">
        <h2 className="text-xl font-semibold mb-4">All Users</h2>

        {/* Search Bar */}
        <div className="mb-4">
          <input
            type="text"
            placeholder="Search by User ID or Role"
            className="border p-2 w-full"
            value={searchTerm}
            onChange={handleSearch}
          />
        </div>

        {/* Users Table */}
        <table className="min-w-full border">
          <thead>
            <tr>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("user_id")}
              >
                User ID{" "}
                {sortConfig.key === "user_id" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("role")}
              >
                Role{" "}
                {sortConfig.key === "role" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
              <th className="border px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.map((user) => (
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
                    onClick={() =>
                      user.suspended
                        ? handleUnsuspendUser(user.user_id)
                        : handleSuspendUser(user.user_id)
                    }
                    className={`${
                      user.suspended ? "bg-green-500" : "bg-blue-500"
                    } text-white px-4 py-2 rounded mr-2`}
                  >
                    {user.suspended ? "Unsuspend" : "Suspend"}
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
    </div>
  );
};

export default AllUsersPage;
