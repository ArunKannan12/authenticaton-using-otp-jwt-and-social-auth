import axios from 'axios';
import React, { useState } from 'react'
import axiosInstance from '../utils/axiosInstance';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';



const ForgotPassword =  () => {
  const navigate = useNavigate()
  const backToLogin = ()=>{
    navigate('/login')
  }

  const [email,setEmail] = useState('')


  const handleSubmit = async (e) =>{
    
    e.preventDefault();

    if (email) {
      try {
        const res = await axiosInstance.post('auth/password-reset/', { email });

        if (res.status === 200) {
          toast.success('A link to reset your password has been sent to your email.');
        }
      } catch (error) {
        // Handle error here (e.g., incorrect email, server issues)
       const errMsg =
            error.response?.data?.email?.[0] ||  // show validation error from 'email' field
            error.response?.data?.detail || 
            'Something went wrong. Please try again.';
          toast.error(errMsg);
      }
    }
    setEmail('')

  }


  return  (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-6 col-md-8 col-12">
          <div className="card shadow rounded-4 border-0">
            <div className="card-body p-4 p-md-5">
              <h2 className="text-center mb-4 fw-bold text-primary">Forgot Password</h2>

              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Enter your email</label>
                  <input
                    type="email"
                    name="email"
                    className="form-control form-control-lg"
                    placeholder="you@example.com"
                    onChange={(e)=>setEmail(e.target.value)}
                    value={email}
                    required
                  />
                </div>


                <div className="d-grid">
                  <button type="submit" className="btn btn-primary btn-lg" >
                   send
                  </button>
                </div>

                <div className="text-center mt-3">
                  <p className="text-muted">
                    Remembered your password?{' '}
                    <span 
                      className="text-primary" 
                      style={{ cursor: 'pointer', textDecoration: 'underline' }}
                      onClick={backToLogin}
                    >
                      Back to Login
                    </span>
                  </p>
                </div>


              </form>

            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword