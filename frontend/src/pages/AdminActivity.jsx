import React, { useEffect, useState } from 'react';
import axios from 'axios';

const AdminActivity = () => {
  const [activityLogs, setActivityLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    // Fetch activity logs when the component mounts
    const fetchActivityLogs = async () => {
      try {
        const response = await axios.get('http://localhost:5000/admin/activity_logs', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`, // Assuming JWT is stored in localStorage
          },
        });
        setActivityLogs(response.data.activity_logs);
      } catch (err) {
        setError('Error fetching activity logs');
      } finally {
        setLoading(false);
      }
    };

    fetchActivityLogs();
  }, []);

  if (loading) {
    return <div>Loading activity logs...</div>;
  }

  if (error) {
    return <div>{error}</div>;
  }

  return (
    <div>
      <h1>Admin Activity Logs</h1>
      <table className="table-auto w-full border-collapse border border-gray-200">
        <thead>
          <tr>
            <th className="border border-gray-300 p-2">User ID</th>
            <th className="border border-gray-300 p-2">Action</th>
            <th className="border border-gray-300 p-2">Timestamp</th>
            <th className="border border-gray-300 p-2">Details</th>
          </tr>
        </thead>
        <tbody>
          {activityLogs.length > 0 ? (
            activityLogs.map((log, index) => (
              <tr key={index} className="hover:bg-gray-100">
                <td className="border border-gray-300 p-2">{log.user_id}</td>
                <td className="border border-gray-300 p-2">{log.action}</td>
                <td className="border border-gray-300 p-2">{log.timestamp}</td>
                <td className="border border-gray-300 p-2">{log.details}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="4" className="border border-gray-300 p-2 text-center">
                No activity logs available.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default AdminActivity;
