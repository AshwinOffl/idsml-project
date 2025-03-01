import React, { useEffect, useState } from "react";
import axios from "axios";
import AdminSidebar from "../components/AdminSidebar"; // Import the AdminSidebar component
import dayjs from "dayjs"; // Import dayjs library for date formatting

const LoginHistoryPage = () => {
  const [loginHistory, setLoginHistory] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [sortConfig, setSortConfig] = useState({ key: null, direction: null });
  const [currentPage, setCurrentPage] = useState(1); // Track current page
  const entriesPerPage = 10; // Number of entries per page

  useEffect(() => {
    fetchLoginHistory();
  }, []);

  const fetchLoginHistory = async () => {
    try {
      const response = await axios.get("http://localhost:5000/admin/login_history", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });

      if (response.data.login_history) {
        // Parse timestamp to Date objects for proper sorting
        const parsedData = response.data.login_history.map((entry) => ({
          ...entry,
          timestamp: new Date(entry.timestamp),
        }));
        setLoginHistory(parsedData);
      } else {
        console.error("Login history not found in response:", response.data);
      }
    } catch (error) {
      console.error("Error fetching login history:", error);
    }
  };

  const handleSearch = (e) => {
    setSearchTerm(e.target.value.toLowerCase());
    setCurrentPage(1); // Reset to first page on search
  };

  const handleSort = (key) => {
    let direction = "asc";
    if (sortConfig.key === key && sortConfig.direction === "asc") {
      direction = "desc";
    }
    setSortConfig({ key, direction });

    const sortedData = [...loginHistory].sort((a, b) => {
      const aValue = key === "timestamp" ? new Date(a[key]) : a[key];
      const bValue = key === "timestamp" ? new Date(b[key]) : b[key];

      if (aValue < bValue) return direction === "asc" ? -1 : 1;
      if (aValue > bValue) return direction === "asc" ? 1 : -1;
      return 0;
    });
    setLoginHistory(sortedData);
  };

  const filteredHistory = loginHistory.filter(
    (entry) =>
      entry.user_id.toString().toLowerCase().includes(searchTerm) ||
      dayjs(entry.timestamp).format("YYYY-MM-DD hh:mm A").toLowerCase().includes(searchTerm) ||
      entry.client_ip.toLowerCase().includes(searchTerm) ||
      entry.user_agent.toLowerCase().includes(searchTerm)
  );

  // Pagination logic
  const totalPages = Math.ceil(filteredHistory.length / entriesPerPage);
  const startIndex = (currentPage - 1) * entriesPerPage;
  const currentEntries = filteredHistory.slice(startIndex, startIndex + entriesPerPage);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  return (
    <div className="flex">
      {/* Sidebar Section */}
      <AdminSidebar />

      {/* Main Content Section */}
      <div className="ml-20 p-4 flex-grow">
        <h1 className="text-2xl font-bold mb-4">Login History</h1>

        {/* Search Bar */}
        <div className="mb-4">
          <input
            type="text"
            placeholder="Search by User ID, Timestamp, IP, or User Agent"
            className="border p-2 w-full"
            value={searchTerm}
            onChange={handleSearch}
          />
        </div>

        {/* Login History Table */}
        <table className="min-w-full border">
          <thead>
            <tr>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("user_id")}
              >
                User ID {sortConfig.key === "user_id" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("timestamp")}
              >
                Timestamp {sortConfig.key === "timestamp" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("client_ip")}
              >
                Client IP {sortConfig.key === "client_ip" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="border px-4 py-2 cursor-pointer"
                onClick={() => handleSort("user_agent")}
              >
                User Agent {sortConfig.key === "user_agent" && (sortConfig.direction === "asc" ? "↑" : "↓")}
              </th>
            </tr>
          </thead>
          <tbody>
            {currentEntries.map((entry, index) => (
              <tr key={index}>
                <td className="border px-4 py-2">{entry.user_id}</td>
                <td className="border px-4 py-2">
                  {dayjs(entry.timestamp).format("YYYY-MM-DD hh:mm A")}
                </td>
                <td className="border px-4 py-2">{entry.client_ip}</td>
                <td className="border px-4 py-2">{entry.user_agent}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination Controls */}
        <div className="flex justify-center mt-4">
          {Array.from({ length: totalPages }, (_, i) => (
            <button
              key={i + 1}
              className={`px-4 py-2 mx-1 border ${
                currentPage === i + 1 ? "bg-blue-500 text-white" : "bg-gray-200"
              }`}
              onClick={() => handlePageChange(i + 1)}
            >
              {i + 1}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default LoginHistoryPage;
