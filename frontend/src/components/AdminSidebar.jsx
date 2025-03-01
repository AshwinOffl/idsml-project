import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

const AdminSidebar = () => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const navigate = useNavigate();

  const toggleSidebar = () => {
    setIsCollapsed((prevState) => !prevState);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div
      className={`${
        isCollapsed ? "w-16" : "w-64"
      } bg-gray-800 text-white fixed top-0 left-0 h-full flex flex-col transition-all duration-300`}
    >
      {/* Sidebar Header */}
      <div className="flex justify-between items-center p-4">
        {!isCollapsed && <h3 className="text-xl font-bold">Admin Dashboard</h3>}
        <button
          onClick={toggleSidebar}
          className="text-white p-2 bg-gray-700 rounded-full"
        >
          {isCollapsed ? ">" : "<"}
        </button>
      </div>

      {/* Sidebar Links */}
      <ul className="flex-grow space-y-2">
        <li>
          <Link
            to="/admin/system-performance"
            className="block py-2 px-4 hover:bg-gray-700 rounded"
          >
            {isCollapsed ? "📊" : "System Performance & Alerts"}
          </Link>
        </li>
        <li>
          <Link
            to="/admin/login-history"
            className="block py-2 px-4 hover:bg-gray-700 rounded"
          >
            {isCollapsed ? "🕒" : "Login History"}
          </Link>
        </li>
        <li>
          <Link
            to="/admin/create-user"
            className="block py-2 px-4 hover:bg-gray-700 rounded"
          >
            {isCollapsed ? "➕" : "Create New User"}
          </Link>
        </li>
        <li>
          <Link
            to="/admin/all-users"
            className="block py-2 px-4 hover:bg-gray-700 rounded"
          >
            {isCollapsed ? "👥" : "All Users"}
          </Link>
        </li>
      </ul>

      {/* Logout Button */}
      <div className="p-4">
        {!isCollapsed && (
          <button
            onClick={handleLogout}
            className="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded w-full"
          >
            Logout
          </button>
        )}
      </div>
    </div>
  );
};

export default AdminSidebar;
