import React from "react";

const ActivityLogs = ({ logs }) => {
  return (
    <div className="mt-8">
      <h2 className="text-xl font-semibold mb-2">Activity Logs</h2>
      <table className="min-w-full border">
        <thead>
          <tr>
            <th className="border px-4 py-2">Message</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={index}>
              <td className="border px-4 py-2">{log.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ActivityLogs;
