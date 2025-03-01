import React from "react";

const PredictionVisualization = ({ predictions }) => {
  return (
    <div className="mb-6">
      <h2 className="text-xl font-semibold mb-2">Real-Time Predictions</h2>
      <div className="border p-4">
        <h3 className="font-semibold">Latest Predictions:</h3>
        <ul>
          {predictions.map((prediction, index) => (
            <li key={index}>{prediction}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default PredictionVisualization;
