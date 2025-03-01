import React, { useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const BulkAction = () => {
  const [actions, setActions] = useState([]);
  const [userId, setUserId] = useState("");
  const [operation, setOperation] = useState("delete");
  const [details, setDetails] = useState({});
  const [loading, setLoading] = useState(false);

  // Add a single action to the list
  const handleAddAction = () => {
    if (!userId) {
      toast.error("User ID is required to add an action.");
      return;
    }

    const newAction = { user_id: userId, operation, details };
    setActions((prevActions) => [...prevActions, newAction]);
    setUserId("");
    setOperation("delete");
    setDetails({});
    toast.success("Action added successfully!");
  };

  // Submit all bulk actions
  const handleBulkSubmit = async () => {
    if (actions.length === 0) {
      toast.error("No actions to submit. Please add actions first.");
      return;
    }

    try {
      setLoading(true);
      const token = localStorage.getItem("token"); // Use the correct token key
      const res = await axios.post(
        "http://localhost:5000/admin/bulk_actions",
        { actions },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setLoading(false);
      setActions([]);
      toast.success("Bulk actions submitted successfully!");
      console.log("Response:", res.data);
    } catch (error) {
      setLoading(false);
      console.error("Error submitting bulk actions:", error);
      toast.error(
        error.response?.data?.error ||
          "An error occurred while submitting bulk actions."
      );
    }
  };

  return (
    <div className="p-6 bg-white rounded shadow-md">
      <h2 className="text-xl font-bold mb-4">Bulk Actions</h2>

      {/* User ID Input */}
      <div className="mb-4">
        <label className="block text-sm font-medium mb-2">User ID:</label>
        <input
          type="text"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          className="border border-gray-300 rounded px-4 py-2 w-full"
        />
      </div>

      {/* Operation Selector */}
      <div className="mb-4">
        <label className="block text-sm font-medium mb-2">Operation:</label>
        <select
          value={operation}
          onChange={(e) => setOperation(e.target.value)}
          className="border border-gray-300 rounded px-4 py-2 w-full"
        >
          <option value="delete">Delete</option>
          <option value="update_role">Update Role</option>
          <option value="suspend">Suspend</option>
          <option value="unsuspend">Unsuspend</option>
          <option value="add_user">Add User</option>
        </select>
      </div>

      {/* Conditional Fields */}
      {operation === "update_role" && (
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">New Role:</label>
          <input
            type="text"
            value={details.role || ""}
            onChange={(e) => setDetails({ ...details, role: e.target.value })}
            className="border border-gray-300 rounded px-4 py-2 w-full"
          />
        </div>
      )}

      {operation === "add_user" && (
        <>
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Password:</label>
            <input
              type="password"
              value={details.user_data?.password || ""}
              onChange={(e) =>
                setDetails({
                  ...details,
                  user_data: { ...details.user_data, password: e.target.value },
                })
              }
              className="border border-gray-300 rounded px-4 py-2 w-full"
            />
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Role:</label>
            <input
              type="text"
              value={details.user_data?.role || ""}
              onChange={(e) =>
                setDetails({
                  ...details,
                  user_data: { ...details.user_data, role: e.target.value },
                })
              }
              className="border border-gray-300 rounded px-4 py-2 w-full"
            />
          </div>
        </>
      )}

      {/* Add Action Button */}
      <button
        onClick={handleAddAction}
        className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
      >
        Add Action
      </button>

      {/* Actions List */}
      <div className="mt-4">
        <h3 className="text-lg font-bold mb-2">Actions to Perform:</h3>
        <ul className="list-disc pl-5">
          {actions.map((action, index) => (
            <li key={index}>
              {action.operation} user {action.user_id}
            </li>
          ))}
        </ul>
      </div>

      {/* Submit Actions Button */}
      <button
        onClick={handleBulkSubmit}
        className={`mt-4 bg-green-500 text-white px-4 py-2 rounded ${
          loading ? "opacity-50 cursor-not-allowed" : "hover:bg-green-600"
        }`}
        disabled={loading}
      >
        {loading ? "Submitting..." : "Submit Bulk Actions"}
      </button>
    </div>
  );
};

export default BulkAction;
