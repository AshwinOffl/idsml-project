import React from "react";

const TopBar = () => {
  return (
    <div className="h-16 bg-gray-100 flex items-center justify-between px-6 shadow">
      <h1 className="text-xl font-bold">Intrusion Detection System</h1>
      <div className="flex items-center space-x-4">
        <span className="text-gray-600">Hello, Admin</span>
        <button className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600">
          Logout
        </button>
      </div>
    </div>
  );
};

export default TopBar;
