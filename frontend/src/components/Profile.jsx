import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import axiosInstance from '../utils/axiosInstance';
import axios from 'axios';

const Profile = () => {
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  
  const user = JSON.parse(localStorage.getItem('user'));
  const jwt_access = JSON.parse( localStorage.getItem('access'));
  useEffect(() => {
    if (!user || !jwt_access) {
    toast.warning('Please log in to view your profile');
    navigate('/login');
    return null;
}

    profileData();
  }, [navigate]);
  
  
  
  const profileData = async () => {
    
    try {
      // Fetch profile data from the backend
      const resp = await axiosInstance.get("auth/profile/");
      console.log('Profile Data:', resp.data);
    } catch (err) {
      console.error('Profile fetch failed', err);
      toast.error('Failed to fetch profile data.');
    } finally {
      setLoading(false);
    }
  };

const handleLogout = async () => {
  const refresh = localStorage.getItem('refresh');
  const jwt_access = localStorage.getItem('access')

  if (!refresh || !jwt_access) {
    toast.error('No refresh token found.');
    return;
  }

  try {
    
    // Just send the refresh token — axiosInstance will attach a valid access token
    const res = await axios.post("http://localhost:8000/api/v1/auth/logout/", { refresh }, {
    headers: {
    'Content-Type': 'application/json',
      },
    });
    
    if (res.status === 200 || res.status === 204) {
      
      toast.success('Logged out successfully!');
    } else {
      toast.warning('Logout response not fully successful.');
    }
  } catch (error) {
    console.error('Logout failed:', error.response?.data || error.message);
    toast.error('Logout failed, clearing session.');

  }finally{
      localStorage.removeItem('user');
      localStorage.removeItem('access');
      localStorage.removeItem('refresh');
      navigate('/login');
  }
};


  if (!user || !jwt_access) {
    toast.warning('Please log in to view your profile');
    navigate('/login');
    return null; // Prevent rendering the profile when not logged in
  }

  return (
    <div className="container d-flex justify-content-center align-items-center min-vh-100">
      <div className="card shadow-lg p-5 rounded-4 text-center w-100" style={{ maxWidth: '500px' }}>
        <h2 className="text-primary mb-3">Welcome, {user?.full_name || 'User'}</h2>
        <p className="text-muted mb-4">Welcome to your profile page!</p>
        {loading ? (
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        ) : (
          <button className="btn btn-danger btn-lg w-100" onClick={handleLogout}>
            Logout
          </button>
        )}
      </div>
    </div>
  );
};

export default Profile;
