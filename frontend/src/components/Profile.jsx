import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import axiosInstance from '../utils/axiosInstance';
import { FaPen, FaUpload, FaTrash, FaTimes } from 'react-icons/fa';

const Profile = () => {
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const navigate = useNavigate();

  const user = JSON.parse(localStorage.getItem('user'));
  const jwt_access = localStorage.getItem('access');

  useEffect(() => {
    if (!user || !jwt_access) {
      toast.warning('Please log in to view your profile');
      navigate('/login');
      return;
    }
    profileData();
  }, []);

  const profileData = async () => {
    try {
      const resp = await axiosInstance.get('auth/profile/');
      setProfile(resp.data);
    } catch {
      toast.error('Failed to fetch profile data.');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleEdit = () => {
    setIsEditing((prev) => !prev);
    setImageFile(null); // reset file on toggle
  };

  const handleImageChange = (e) => {
    setImageFile(e.target.files[0]);
  };

  const handleImageUpload = async () => {
    if (!imageFile) {
      toast.warning('Please select an image first.');
      return;
    }
    try {
      const formData = new FormData();
      formData.append('custom_user_profile', imageFile);

      const resp = await axiosInstance.patch('auth/profile/', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      setProfile(resp.data);
      toast.success('Profile picture updated!');
      setIsEditing(false);
      setImageFile(null);
    } catch {
      toast.error('Failed to update profile picture.');
    }
  };

  const handleImageDelete = async () => {
    try {
      const resp = await axiosInstance.patch('auth/profile/', {
        custom_user_profile: null,
      });

      setProfile(resp.data);
      toast.success('Profile picture deleted!');
      setIsEditing(false);
      setImageFile(null);
    } catch {
      toast.error('Failed to delete profile picture.');
    }
  };

  if (!user || !jwt_access) {
    return null;
  }

  const isCustomUser = profile?.auth_provider?.toLowerCase() === 'email';

  const customUserProfileUrl = profile?.custom_user_profile
    ? `http://localhost:8000${profile.custom_user_profile}`
    : 'https://cdn-icons-png.flaticon.com/512/847/847969.png';

  const socialProfilePic = user?.profile_picture || null;

  return (
    <div className="container d-flex justify-content-center align-items-center min-vh-100">
      <div className="card shadow-lg p-5 rounded-4 text-center w-100" style={{ maxWidth: '500px' }}>
        <h2 className="text-primary mb-3">Welcome, {user?.full_name || 'User'}</h2>

        {isCustomUser ? (
          <div className="d-flex justify-content-center align-items-center mb-4" style={{ maxWidth: '320px', margin: '0 auto'  }}>
            <img
              src={customUserProfileUrl}
              alt="Profile"
              className="rounded-circle shadow"
              style={{ width: '120px', height: '120px', objectFit: 'cover'  }}
            />
            <button
              type="button"
              onClick={handleToggleEdit}
              aria-label="Edit profile picture"
              title="Edit profile picture"
              className="btn btn-light ms-3 p-1 rounded-circle shadow-sm"
              style={{ width: '32px', height: '32px' }}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#f0f0f0')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '')}
            >
              <FaPen size={16} color="#007bff" />
            </button>

            {isEditing && (
  <div className="d-flex flex-column gap-2 ms-3" style={{ minWidth: '120px' }}>
    <input
      type="file"
      accept="image/*"
      onChange={handleImageChange}
      className="form-control form-control-sm"
      style={{ cursor: 'pointer' }}
    />
    <div className="d-flex gap-2 mt-2">
      <button
        className="btn btn-success btn-sm d-flex align-items-center justify-content-center"
        onClick={handleImageUpload}
        disabled={!imageFile}
        title="Upload"
      >
        <FaUpload className="me-1" /> Upload
      </button>
      <button
        className="btn btn-danger btn-sm d-flex align-items-center justify-content-center"
        onClick={handleImageDelete}
        title="Delete"
      >
        <FaTrash className="me-1" /> Delete
      </button>
      <button
        className="btn btn-secondary btn-sm d-flex align-items-center justify-content-center"
        onClick={handleToggleEdit}
        title="Cancel"
      >
        <FaTimes className="me-1" /> Cancel
      </button>
    </div>
  </div>
)}

          </div>
        ) : (
          <div className="mb-4 mx-auto" style={{ width: '120px', height: '120px' }}>
            <img
              src={socialProfilePic || customUserProfileUrl}
              alt="Profile"
              className="rounded-circle shadow"
              style={{ width: '120px', height: '120px', objectFit: 'cover' }}
            />
          </div>
        )}

        <p className="text-muted mb-4">Welcome to your profile page!</p>

        {loading ? (
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        ) : (
          <button
            className="btn btn-danger btn-lg w-100"
            onClick={() => {
              localStorage.clear();
              navigate('/login');
              toast.success('Logged out successfully!');
            }}
          >
            Logout
          </button>
        )}
      </div>
    </div>
  );
};

export default Profile;
