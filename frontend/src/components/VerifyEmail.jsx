import React, { useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import {  useNavigate } from 'react-router-dom';

const VerifyEmail = () => { 
  const [resendLoading, setResendLoading] = useState(false);
  const [otp,setOtp]=useState('')
  const [loading, setLoading] = useState(false);
  const navigate=useNavigate('')
  
  // Define this above your return statement
  const handleOtpChange = (e) => {
    setOtp(e.target.value);
  };


  const handleSubmit= async (e) =>{
    e.preventDefault()
    const email = localStorage.getItem("email");
    if (!email) {
      toast.error("Email not found. Please register again.");
      navigate("/");
      return;
    }if (!otp) {
      toast.error("Please enter the OTP");
      return;
    }

    try {
      setLoading(true)
      const response = await axios.post("http://localhost:8000/api/v1/auth/verify-otp/", {
        email: email,
        otp: otp,
      });

      if (response.status === 200) {
        toast.success(response.data.message);
        localStorage.removeItem("email"); // optional cleanup
        navigate("/login");
      }
    } catch (error) {
      if (error.response && error.response.data && error.response.data.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error("Something went wrong");
      }
    }finally{
      setLoading(false)
    }
  };

  const handleResendOtp = async () => {
    const email = localStorage.getItem("email");

    if (!email) {
      toast.error("Email not found. Please register again.");
      navigate("/");
      return;
    }
    setResendLoading(true);
    try {
      const res = await axios.post("http://localhost:8000/api/v1/auth/send-otp/", {
        email: email,
      });

      if (res.status === 200) {
        toast.success(res.data.message || "OTP resent successfully");
      }
    } catch (err) {
      toast.error(err.response?.data?.error || "Failed to resend OTP");
    }finally{
      setResendLoading(false)
  }
  };

  return (
    <div className="container min-vh-100 d-flex align-items-center justify-content-center">
    <div className="col-md-5">
      <div className="card shadow p-4">
        <div className="card-body">
          <h4 className="text-center mb-4">Enter Your OTP Code</h4>
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="otp" className="form-label">OTP Code</label>
              <input
                type="text"
                name="otp"
                className="form-control"
                placeholder="Enter 6-digit code"
                value={otp}
                onChange={handleOtpChange}
              />
            </div>
            <div className="d-grid mb-2">
              <button type="submit" className="btn btn-success" disabled={loading}>
                {loading ? "Verifying..." : "Verify"}
              </button>
            </div>
          </form>
          <div className="text-center">
            <p>Didn't receive the code?</p>
            <button onClick={handleResendOtp} className="btn btn-link text-decoration-none" disabled={resendLoading}>
              {resendLoading ? 'Resending' : 'resend OTP'}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
  );
};

export default VerifyEmail;
