import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Signup, Login, VerifyEmail, ForgotPassword, Profile,ResetPassword } from './components/Index';

import { ToastContainer } from 'react-toastify';

function App() {
  return (
    <Router>
      <ToastContainer/>
      <Routes>
        <Route path="/" element={<Signup />} />
        <Route path="/login" element={<Login />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/otp/verify-otp" element={<VerifyEmail />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/password-reset-confirm/:uid/:token" element={<ForgotPassword />} />
      </Routes>
    </Router>
  );
}

export default App;
