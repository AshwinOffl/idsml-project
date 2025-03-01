import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ToastContainer } from "react-toastify"; // Import ToastContainer
import { PredictionProvider } from "./context/PredictionContext"; // Import PredictionContext
import LoginPage from "./pages/LoginPage";
import AdminPage from "./pages/AdminPage";
import UserPage from "./pages/UserPage";
import Dashboard from "./pages/Dashboard";
import Notifications from "./pages/Notifications";
import UserProfile from "./pages/UserProfile";
import Settings from "./pages/Settings"; // New import for Settings page
import ManualPrediction from "./pages/ManualPrediction"; // Import ManualPrediction page
import AdminActivity from "./pages/AdminActivity";
import SystemPerformancePage from "./pages/SystemPerformancePage";
import LoginHistoryPage from "./pages/LoginHistoryPage";
import CreateNewUserPage from "./pages/CreateNewUserPage";
import AllUsersPage from "./pages/AllUsersPage";
import BulkAction from "./pages/BulkAction";
import "react-toastify/dist/ReactToastify.css"; // Import toast styling

const App = () => {
  return (
    <PredictionProvider>
      <Router>
        <Routes>
          {/* Login Routes */}
          <Route path="/" element={<LoginPage />} />
          <Route path="/login" element={<LoginPage />} />

          {/* Admin Route */}
          <Route path="/adminpage" element={<AdminPage />} />
          <Route path="/admin/system-performance" element={<SystemPerformancePage />} />
          <Route path="/admin/login-history" element={<LoginHistoryPage />} />
          <Route path="/admin/create-user" element={<CreateNewUserPage />} />
          <Route path="/admin/all-users" element={<AllUsersPage />} />
          <Route path="/admin/bulkaction" element={<BulkAction />} />

          {/* User Routes */}
          <Route path="/userpage" element={<UserPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/profile" element={<UserProfile />} />

          {/* Settings Route */}
          <Route path="/settings" element={<Settings />} /> {/* New route for Settings */}
          <Route path="/admin_activity" element={<AdminActivity />} /> {/* New route for Settings */}

          {/* Manual Prediction Route */}
          <Route path="/manual-prediction" element={<ManualPrediction />} /> {/* New route for Manual Prediction */}
        </Routes>

        {/* ToastContainer for showing toasts globally */}
        <ToastContainer />
      </Router>
    </PredictionProvider>
  );
};

export default App;
