import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

const Sidebar = () => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const navigate = useNavigate();

  const toggleSidebar = () => {
    setIsCollapsed((prevState) => !prevState);
  };

  const handleLogout = () => {
    // Clear authentication data (if stored)
    localStorage.removeItem("token");
    navigate("/login"); // Redirect to login page
  };

  return (
    <div
      className={`${
        isCollapsed ? "w-16" : "w-1/4"
      } bg-gray-800 text-white p-4 flex flex-col fixed top-0 left-0 h-full transition-all duration-300 overflow-hidden`}
    >
      {/* Sidebar Header */}
      <div className="flex justify-between items-center mb-4">
        <h2 className={`text-2xl font-bold ${isCollapsed ? "hidden" : ""}`}>
          IDS System
        </h2>
        <button
          onClick={toggleSidebar}
          className="text-white p-2 bg-gray-700 rounded-full"
        >
          {isCollapsed ? ">" : "<"}
        </button>
      </div>

      {/* Sidebar Links */}
      <ul className="space-y-2 flex-grow">
        <li>
          <Link
            to="/userpage"
            className="text-white hover:bg-gray-700 p-2 block rounded"
          >
            {isCollapsed ? "🏠" : "Home"}
          </Link>
        </li>
        <li>
          <Link
            to="/dashboard"
            className="text-white hover:bg-gray-700 p-2 block rounded"
          >
            {isCollapsed ? "📊" : "Dashboard"}
          </Link>
        </li>
        <li>
          <Link
            to="/notifications"
            className="text-white hover:bg-gray-700 p-2 block rounded"
          >
            {isCollapsed ? "🔔" : "Notifications"}
          </Link>
        </li>
        <li>
          <Link
            to="/settings"
            className="text-white hover:bg-gray-700 p-2 block rounded"
          >
            {isCollapsed ? "⚙️" : "Settings"}
          </Link>
        </li>
      </ul>

      {/* Logout Button */}
      {!isCollapsed && (
        <button
          onClick={handleLogout}
          className="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded mb-4"
        >
          Logout
        </button>
      )}

      {/* Footer */}
      {!isCollapsed && (
        <div className="text-sm text-gray-400 mt-auto">
          <p>&copy; 2024 IDS System by Ashwin</p>
        </div>
      )}
    </div>
  );
};

export default Sidebar;
