import React, { useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import AdminSidebar from "../components/AdminSidebar"; // Import Sidebar

const CreateNewUser = () => {
  const [newUser, setNewUser] = useState({ user_id: "", password: "", role: "user" });

  // Create a new user
  const handleCreateUser = async () => {
    try {
      await axios.post("http://localhost:5000/admin/create_user", newUser, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
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

  return (
    <div className="flex">
      <AdminSidebar /> {/* Add the Sidebar */}
      <div className="ml-20 p-6 flex-1">
        <h1 className="text-2xl font-bold mb-4">Create New User</h1>

        {/* Create New User Section */}
        <div className="mb-6">
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
      </div>
    </div>
  );
};

export default CreateNewUser;
