import { useEffect, useState } from "react";
import { usePredictionContext } from "../context/PredictionContext";
import Sidebar from "../components/Sidebar";
import { useNavigate } from "react-router-dom";

const Notifications = () => {
  const { packets, setPackets } = usePredictionContext();
  const [allPackets, setAllPackets] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState("");
  const [filteredPackets, setFilteredPackets] = useState([]);
  const [sortConfig, setSortConfig] = useState({ key: "timestamp", direction: "desc" });
  const [excludeNormal, setExcludeNormal] = useState(false);
  const entriesPerPage = 10;
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/login");
    }

    setAllPackets((prevPackets) => [...packets, ...prevPackets].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));

    let filtered = allPackets.filter(
      (packet) =>
        (excludeNormal ? packet.prediction !== "Normal" : true) &&
        (packet.prediction.toLowerCase().includes(searchQuery.toLowerCase()) ||
        packet.timestamp.toLowerCase().includes(searchQuery.toLowerCase()))
    );

    if (sortConfig.key) {
      filtered = filtered.sort((a, b) => {
        if (a[sortConfig.key] < b[sortConfig.key]) {
          return sortConfig.direction === "asc" ? -1 : 1;
        }
        if (a[sortConfig.key] > b[sortConfig.key]) {
          return sortConfig.direction === "asc" ? 1 : -1;
        }
        return 0;
      });
    }

    setFilteredPackets(filtered);
  }, [searchQuery, packets, allPackets, sortConfig, excludeNormal, navigate]);

  const handleSort = (key) => {
    setSortConfig((prevSort) => {
      const direction =
        prevSort.key === key && prevSort.direction === "asc" ? "desc" : "asc";
      return { key, direction };
    });
  };

  const toggleExcludeNormal = () => {
    setExcludeNormal((prev) => !prev);
  };

  const startIndex = (currentPage - 1) * entriesPerPage;
  const currentPackets = filteredPackets.slice(
    startIndex,
    startIndex + entriesPerPage
  );

  const handleNextPage = () => {
    if (startIndex + entriesPerPage < filteredPackets.length) {
      setCurrentPage((prevPage) => prevPage + 1);
    }
  };

  const handlePreviousPage = () => {
    if (currentPage > 1) {
      setCurrentPage((prevPage) => prevPage - 1);
    }
  };

  const getSortIndicator = (key) => {
    if (sortConfig.key === key) {
      return sortConfig.direction === "asc" ? " ▲" : " ▼";
    }
    return "";
  };

  return (
    <div className="ml-32 h-screen flex">
      <Sidebar />
      <div className="flex-1 p-4">
        <h1 className="text-2xl font-bold mb-4">Real-Time Notifications</h1>

        <div className="mb-4 flex justify-between items-center">
          <input
            type="text"
            placeholder="Search notifications..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-md w-1/2"
          />
          <button
            onClick={() => setSearchQuery("")}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Clear Search
          </button>
          <button
            onClick={toggleExcludeNormal}
            className={`px-4 py-2 rounded ${excludeNormal ? "bg-red-500" : "bg-gray-500"} text-white hover:bg-gray-600`}
          >
            {excludeNormal ? "Show All" : "Exclude Normal"}
          </button>
        </div>

        {filteredPackets.length > 0 ? (
          <>
            <table className="min-w-full border-collapse border border-gray-200">
              <thead>
                <tr className="bg-gray-100">
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("id")}>ID{getSortIndicator("id")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("prediction")}>Prediction{getSortIndicator("prediction")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("confidence")}>Confidence{getSortIndicator("confidence")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("timestamp")}>Timestamp{getSortIndicator("timestamp")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("src_ip")}>Source IP{getSortIndicator("src_ip")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("dst_ip")}>Destination IP{getSortIndicator("dst_ip")}</th>
                  <th className="border border-gray-300 px-4 py-2 cursor-pointer" onClick={() => handleSort("length")}>Packet Size{getSortIndicator("length")}</th>
                  <th className="border border-gray-300 px-4 py-2">Status</th>
                  <th className="border border-gray-300 px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {currentPackets.map((packet, index) => (
                  <tr key={index} className={packet.prediction !== "Normal" ? "bg-red-100" : "bg-green-100"}>
                    <td className="border border-gray-300 px-4 py-2">{startIndex + index + 1}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.prediction}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.confidence}%</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.timestamp}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.src_ip}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.dst_ip}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.length}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.prediction === "Normal" ? "Safe" : "Pending"}</td>
                    <td className="border border-gray-300 px-4 py-2">{packet.prediction === "Normal" ? "Resolved" : "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="flex justify-between items-center mt-4">
              <button onClick={handlePreviousPage} disabled={currentPage === 1} className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">Previous</button>
              <span>Page {currentPage} of {Math.ceil(filteredPackets.length / entriesPerPage)}</span>
              <button onClick={handleNextPage} disabled={startIndex + entriesPerPage >= filteredPackets.length} className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">Next</button>
            </div>
          </>
        ) : (<p className="text-gray-600">No notifications yet.</p>)}
      </div>
    </div>
  );
};

export default Notifications;