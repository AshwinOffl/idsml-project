import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../services/authService";
import axios from "axios";

const LoginPage = () => {
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(""); // Reset error state

    try {
      // Perform login
      const result = await login(userId, password);

      if (result.success) {
        // Check if user is suspended
        if (result.suspended) {
          setError("Your account is suspended. Please contact support.");
          return;
        }

        // Store JWT token in localStorage
        localStorage.setItem("token", result.token);

        // Log the login activity
        logLoginActivity();

        // Redirect user based on their role
        if (result.role === "admin") {
          navigate("/adminpage");
        } else if (result.role === "user") {
          navigate("/userpage");
        } else {
          setError("Invalid role. Please contact support.");
        }
      } else {
        // Display appropriate error message
        setError(result.message || "Login failed. Please try again.");
      }
    } catch (error) {
      // Log the entire error response for debugging
      console.error("Login Error Response: ", error.response); // Log the error response

      // Handle specific backend error
      if (error.response) {
        switch (error.response.status) {
          case 403:
            setError("Your account has been suspended. Please contact support.");
            break;
          case 404:
            setError("User not found. Please check your credentials.");
            break;
          case 401:
            setError("Invalid password. Please try again.");
            break;
          default:
            setError("Unexpected error. Please contact support.");
        }
      } else {
        // Handle errors that don’t have a response (e.g., network issues)
        setError("Network error. Please check your internet connection.");
      }
    }
  };

  // Log the login activity
  const logLoginActivity = async () => {
    try {
      const response = await axios.post(
        "http://localhost:5000/admin/login_history", // Your backend endpoint
        {
          user_id: userId,
          client_ip: window.location.hostname, // Example; you can get actual IP via your backend
          user_agent: navigator.userAgent,
        },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      console.log("Login activity logged:", response.data);
    } catch (error) {
      console.error("Error logging login activity:", error);
    }
  };

  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100">
      <div className="w-full max-w-md p-8 space-y-4 bg-white rounded-lg shadow-lg">
        <h2 className="text-2xl font-bold text-center text-gray-800">Login</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="user_id"
              className="block text-sm font-medium text-gray-700"
            >
              User ID
            </label>
            <input
              type="text"
              id="user_id"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              required
              className="w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-gray-700"
            >
              Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <button
            type="submit"
            className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            Login
          </button>
        </form>

        {error && (
          <div className="mt-4 text-red-600 text-center">
            <p>{error}</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoginPage;
