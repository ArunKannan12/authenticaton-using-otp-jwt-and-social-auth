import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Signup, Login, VerifyEmail, ForgotPassword, Profile, ResetPassword } from './components/Index';
import { ToastContainer } from 'react-toastify';
import useAutoLogout from './utils/useAutoLogout';
import Modal from './utils/Modal';

function AppRoutes() {
  const { modalOpen, onConfirm, onClose } = useAutoLogout(); // ✅ Now safely inside Router context

  return (
    <>
      <ToastContainer />
      <Modal
        isOpen={modalOpen}
        title="Session Expiring"
        message="You will be logged out soon due to inactivity. Do you want to stay logged in?"
        onConfirm={onConfirm}
        onClose={onClose}
      />
      <Routes>
        <Route path="/" element={<Signup />} />
        <Route path="/login" element={<Login />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/otp/verify-otp" element={<VerifyEmail />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/password-reset-confirm/:uid/:token" element={<ResetPassword />} />
      </Routes>
    </>
  );
}

function App() {
  return (
    <Router>
      <AppRoutes />
    </Router>
  );
}

export default App;
