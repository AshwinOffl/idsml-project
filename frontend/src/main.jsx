import React from "react";
import ReactDOM from "react-dom/client"; // Import createRoot from react-dom/client
import App from "./App"; // Ensure path is correct
import "./index.css"; // Optional: Tailwind or global styles

// Use createRoot instead of ReactDOM.render
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
