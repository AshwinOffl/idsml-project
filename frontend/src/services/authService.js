// src/services/authService.js

export const login = async (userId, password) => {
  try {
    const response = await fetch("http://localhost:5000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ user_id: userId, password: password }),
    });

    if (response.ok) {
      const data = await response.json();
      return {
        success: true,
        token: data.token, // JWT token
        role: data.role,  // User role (admin/user)
      };
    } else if (response.status === 401) {
      return { success: false, message: "Invalid credentials. Please try again." };
    } else if (response.status === 500) {
      return { success: false, message: "Server error. Please try again later." };
    } else {
      return { success: false, message: "Unexpected error. Please contact support." };
    }
  } catch (err) {
    console.error("Login failed:", err);
    return { success: false, message: "An unexpected error occurred. Please try again." };
  }
};
