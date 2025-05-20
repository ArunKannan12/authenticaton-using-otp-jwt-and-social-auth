import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import { AiFillEye, AiFillEyeInvisible } from 'react-icons/ai'; // Import eye icons

const Login = () => {
  const [loginData, setLoginData] = useState({
    email: '',
    password1: ''
  });

  const [error, setError] = useState('');
  const navigate = useNavigate();

  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false); // State to toggle password visibility

  const { email, password1 } = loginData;

  
  useEffect(()=>{
    
    const user = JSON.parse(localStorage.getItem('user'));
    const jwt_access = localStorage.getItem('access');
    const jwt_refresh =localStorage.getItem('refresh');
    if (user && jwt_access && jwt_refresh) {
      navigate('/profile')
      return 
    }
  },[navigate])


  const handleOnChange = (e) => {
    setLoginData({ ...loginData, [e.target.name]: e.target.value });
  };

  const handlePasswordToggle = () => {
    setShowPassword(!showPassword); // Toggle visibility
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!email || !password1) {
      setError('Email and password are required');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const res = await axios.post("http://localhost:8000/api/v1/auth/login/", loginData);
      const response = res.data;
      
      
      const user={
        "full_name":response.full_name,
        "email":response.email
      }
      if (res.status === 200) {
        localStorage.setItem("user",JSON.stringify(user))
        localStorage.setItem('access',response.access_token)
        localStorage.setItem('refresh',response.refresh_token)

        
        navigate('/profile');
        toast.success('Login successful!');
      }
    } catch (error) {

      const status = error.response?.status;
      const errDetail = error.response?.data?.detail || '';

      if (status === 401 || status === 400) {
        if ( 
          errDetail === "This account is registered via Google. Please use Google login instead." ||
          errDetail === "This account is registered via Facebook. Please use Facebook login instead."
          ) {
          setError(errDetail);
          toast.error(errDetail)
    
        } else {
        const fallback = errDetail || 'Invalid email or password';
        setError(fallback);
        toast.error(fallback);
        }
      }else{
        setError('Something went wrong');
        toast.error('Something went wrong, please try again');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-6 col-md-8 col-12">
          <div className="card shadow rounded-4 border-0">
            <div className="card-body p-4 p-md-5">
              <h2 className="text-center mb-4 fw-bold text-primary">Login</h2>

              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Email Address</label>
                  <input
                    type="email"
                    name="email"
                    className="form-control form-control-lg"
                    placeholder="you@example.com"
                    value={email}
                    onChange={handleOnChange}
                  />
                </div>

                <div className="mb-3 position-relative">
                  <label htmlFor="password1" className="form-label">Password</label>
                  <input
                    type={showPassword ? "text" : "password"} // Toggle input type
                    name="password1"
                    className="form-control form-control-lg pe-5"
                    placeholder="********"
                    value={password1}
                    onChange={handleOnChange}
                  />
                  <span
                    onClick={handlePasswordToggle}
                    style={{
                      position: 'absolute',
                      top: '73%',
                      right: '1rem',
                      transform: 'translateY(-50%)',
                      cursor: 'pointer',
                      color: 'rgb(8 8 8)'
                    }}
                    
                  >
                    {showPassword ? <AiFillEyeInvisible size={24} /> : <AiFillEye size={24} />}
                  </span>
                </div>

                  <div className="mb-3 text-end">
                    <span 
                      className="text-primary" 
                      style={{ cursor: 'pointer', fontSize: '0.9rem' }} 
                      onClick={() => navigate('/forgot-password')}
                    >
                    Forgot password?
                    </span>
                  </div>

                {error && <p className="text-danger">{error}</p>}

                <div className="d-grid">
                  <button type="submit" className="btn btn-primary btn-lg" disabled={isLoading}>
                    {isLoading ? 'Logging in...' : 'Login'}
                  </button>
                </div>
                  
                  <div className="text-center mt-3">
                  <p className="text-muted">
                    Don't have an account? 
                    <span 
                      className="text-primary" 
                      style={{ cursor: 'pointer' }} 
                      onClick={() => navigate('/')}
                    >
                      Register
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

export default Login;
