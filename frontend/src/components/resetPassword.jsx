import React, { useState } from 'react'
import { useNavigate,useParams } from 'react-router-dom'
import axiosInstance from '../utils/axiosInstance'


const ResetPassword = () => {
    const navigate = useNavigate()
    const {uid,token} = useParams()
    const [newPasswords, setNewPasswords] = useState({
        password:'',
        confirm_password:''
    })

    const handleChange = (e) =>{
       setNewPasswords({ ...newPasswords, [e.target.name]: e.target.value });

    }
    
    const data = {
        'password':newPasswords.password,
        'confirm_password':newPasswords.confirm_password,
        'uidb64':uid,
        'token':token
    }

    const handleSubmit = async (e) =>{
        e.preventDefault()

        //make api call
        const response = await axiosInstance.patch('auth/set-new-password/',data)

    }
    
    return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-6 col-md-8 col-12">
          <div className="card shadow rounded-4 border-0">
            <div className="card-body p-4 p-md-5">
              <h2 className="text-center mb-4 fw-bold text-primary">Reset Password</h2>

              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="newPassword" className="form-label">New Password</label>
                  <input
                    type="password"
                    className="form-control form-control-lg"
                    name="Password"
                    placeholder="Enter new password"
                    value={newPasswords.password}
                    onChange={handleChange}
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                  <input
                    type="password"
                    className="form-control form-control-lg"
                    name="confirm_password"
                    placeholder="Confirm new password"
                    value={newPasswords.confirm_password}
                    onChange={handleChange}
                  />
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
  )
}

export default ResetPassword