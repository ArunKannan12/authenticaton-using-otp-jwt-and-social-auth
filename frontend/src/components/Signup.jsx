import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useGoogleLogin,GoogleLogin } from '@react-oauth/google';


const Signup = () => {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    first_name: "",
    last_name: "",
    password1: "",
    password2: "",
  });

  const { email, first_name, last_name, password1, password2 } = formData;
  const [errors, setErrors] = useState();

  const user = JSON.parse(localStorage.getItem('user'));
  const jwt_access = JSON.parse(localStorage.getItem('access'));
  const jwt_refresh = JSON.parse(localStorage.getItem('refresh'));

  useEffect(() => {
    if (user && jwt_access && jwt_refresh) {
      navigate('/profile');
      return;
    }
  }, [navigate]);

  const handleOnChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = {};

    // Client-side validation
    if (!email) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(email)) newErrors.email = "Invalid email format";

    if (!first_name) newErrors.first_name = 'First name is required';
    if (!last_name) newErrors.last_name = 'Last name is required';
    if (!password1) newErrors.password1 = 'Password is required';
    else if (password1.length < 8) newErrors.password1 = 'Password must be at least 8 characters';
    if (!password2) newErrors.password2 = 'Confirm password is required';
    else if (password1 !== password2) newErrors.password2 = 'Passwords do not match';

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    try {
      const res = await axios.post("http://localhost:8000/api/v1/auth/register/", formData);
      const response = res.data;

      if (res.status === 201) {
        localStorage.setItem('emailForVerification', email);
        toast.success(response.message);
        setErrors(null);
        navigate("/otp/verify-otp");
      }
    } catch (err) {
      const apiError = err.response?.data?.detail || "Registration failed. Please try again";
      setErrors({ api: apiError });
    }

    localStorage.setItem("email", formData.email);
  };

  // Handle Google login success
const handleGoogleLogin= async (credentialResponse) => {
    try {
      const res = await axios.post('http://localhost:8000/api/v1/auth/social-login/', {
        id_token: credentialResponse.credential,  // ✅ Correct key
      });

      if (res.status === 200) {
        const { full_name, email, access_token, refresh_token } = res.data;

        localStorage.setItem('access', JSON.stringify(access_token));
        localStorage.setItem('refresh', JSON.stringify(refresh_token));
        localStorage.setItem('user', JSON.stringify({full_name,email}));
        console.log('google',res.data)
        toast.success(`Welcome ${full_name}`);
        navigate('/profile');
      }
    } catch (error) {
      console.error('Google login failed:', error.response?.data || error.message);
      toast.error('Google login failed. Please try again.');
    }
  }
  
  

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-6 col-md-8 col-12">
          <div className="card shadow rounded-4 border-0">
            <div className="card-body p-4 p-md-5">
              <h2 className="text-center mb-4 fw-bold text-primary">Create Account</h2>
              <form onSubmit={handleSubmit}>

                {errors && <p className="text-danger">{errors.api}</p>}

                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Email Address</label>
                  <input type="email"
                    name="email"
                    className="form-control form-control-lg"
                    placeholder="you@example.com"
                    value={email}
                    onChange={handleOnChange} />
                </div>

                <div className="mb-3">
                  <label htmlFor="first_name" className="form-label">First Name</label>
                  <input type="text"
                    name="first_name"
                    className="form-control form-control-lg"
                    placeholder="John"
                    value={first_name}
                    onChange={handleOnChange} />
                </div>

                <div className="mb-3">
                  <label htmlFor="last_name" className="form-label">Last Name</label>
                  <input type="text"
                    name="last_name"
                    className="form-control form-control-lg"
                    placeholder="Doe"
                    value={last_name}
                    onChange={handleOnChange} />
                </div>

                <div className="mb-3">
                  <label htmlFor="password1" className="form-label">Password</label>
                  <input type="password"
                    name="password1"
                    className="form-control form-control-lg"
                    placeholder="********"
                    value={password1}
                    onChange={handleOnChange} />
                </div>

                <div className="mb-4">
                  <label htmlFor="password2" className="form-label">Confirm Password</label>
                  <input type="password"
                    name="password2"
                    className="form-control form-control-lg"
                    placeholder="********"
                    value={password2}
                    onChange={handleOnChange} />
                </div>

                <div className="d-grid">
                  <button type="submit" className="btn btn-primary btn-lg">Create Account</button>
                </div>

                <div className="text-center my-4">
                  <p className="text-muted">Already have an account?
                    <button
                      className="btn btn-link text-primary"
                      onClick={() => navigate('/login')}
                    >
                      Login
                    </button>
                  </p>
                </div>
              </form>

              <div className="text-center my-4">
                <h5 className="text-muted mb-3">or</h5>

                <div className="d-grid gap-3 col-12 col-md-8 mx-auto">
                  <button className="btn btn-dark btn-lg">
                    <i className="bi bi-github me-2"></i> Sign up with GitHub
                  </button>
                <GoogleLogin
                onSuccess={handleGoogleLogin}
                onError={()=>toast.error('Googlee sign-in failed')}/>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Signup;
