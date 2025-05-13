import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axiosInstance from '../utils/axiosInstance';
import validatePassword from '../utils/valifatePassword';
import { FaEye, FaEyeSlash } from 'react-icons/fa';

const ResetPassword = () => {
  const navigate = useNavigate();
  const { uid, token } = useParams();

  const [newPasswords, setNewPasswords] = useState({
    password: '',
    confirm_password: '',
  });

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  
  // Use the state for password validation feedback
  const [passwordValidation, setPasswordValidation] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    number: false,
    symbol: false,
  });

 // Update password validation when password changes
  useEffect(() => {
    setPasswordValidation(validatePassword(newPasswords.password));
  }, [newPasswords.password]);




  const handleChange = (e) => {
    setNewPasswords({ ...newPasswords, [e.target.name]: e.target.value });
    setError('');
    setSuccess('');
  };

  const data = {
    password: newPasswords.password,
    confirm_password: newPasswords.confirm_password,
    uidb64: uid,
    token: token,
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError('');
    setSuccess('');

    // Check if passwords match
    if (newPasswords.password !== newPasswords.confirm_password) {
      setError('Passwords do not match.');
      return;
    }

    // If password doesn't meet all validation criteria, show error
    const validationError = Object.values(passwordValidation).includes(false);
    if (validationError) {
      setError(validationError);
      return;
    }

    // Make API call to reset password
    try {
      await axiosInstance.post('auth/set-new-password/', data);
      setSuccess('Password reset successful! Redirecting to login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Something went wrong. Please try again.');
    }
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-6 col-md-8 col-12">
          <div className="card shadow rounded-4 border-0">
            <div className="card-body p-4 p-md-5">
              <h2 className="text-center mb-4 fw-bold text-primary">Reset Password</h2>

              <form onSubmit={handleSubmit}>
                <div className="mb-3 position-relative">
                  <label htmlFor="newPassword" className="form-label">New Password</label>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    className="form-control form-control-lg"
                    name="password"
                    placeholder="Enter new password"
                    value={newPasswords.password}
                    onChange={handleChange}
                  />
                  <span
                    className="position-absolute top-50 end-0 translate-middle-y pe-3"
                    style={{ cursor: 'pointer' }}
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <FaEyeSlash /> : <FaEye />}
                  </span>
                </div>

                <ul className="text-muted small">
                  <li style={{ color: passwordValidation.length ? 'green' : 'red' }}>At least 8 characters</li>
                  <li style={{ color: passwordValidation.uppercase ? 'green' : 'red' }}>Contains uppercase letter</li>
                  <li style={{ color: passwordValidation.lowercase ? 'green' : 'red' }}>Contains lowercase letter</li>
                  <li style={{ color: passwordValidation.number ? 'green' : 'red' }}>Contains number</li>
                  <li style={{ color: passwordValidation.symbol ? 'green' : 'red' }}>Contains special character (@$!%*?&)</li>
                </ul>

                <div className="mb-3 position-relative">
                  <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                  <input
                    type={showConfirm ? 'text' : 'password'}
                    className="form-control form-control-lg"
                    name="confirm_password"
                    placeholder="Confirm new password"
                    value={newPasswords.confirm_password}
                    onChange={handleChange}
                  />
                  <span
                    className="position-absolute top-50 end-0 translate-middle-y pe-3"
                    style={{ cursor: 'pointer' }}
                    onClick={() => setShowConfirm(!showConfirm)}
                  >
                    {showConfirm ? <FaEyeSlash /> : <FaEye />}
                  </span>
                </div>

                {error && <p className="text-danger">{error}</p>}
                {success && <p className="text-success">{success}</p>}

                <div className="d-grid mt-3">
                  <button type="submit" className="btn btn-primary btn-lg">Reset Password</button>
                </div>

                <div className="text-center mt-3">
                  <a href="/login" className="text-primary" style={{ cursor: 'pointer' }}>
                    Back to Login
                  </a>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
