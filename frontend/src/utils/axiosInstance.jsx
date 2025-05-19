import axios from "axios";
import dayjs from 'dayjs';
import { jwtDecode } from 'jwt-decode'; // Try this if default import fails

const baseURL = "http://localhost:8000/api/v1/";

const axiosInstance = axios.create({
  baseURL: baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
});

axiosInstance.interceptors.request.use(async (req) => {
  const access = localStorage.getItem("access");
  const refresh = localStorage.getItem("refresh");


  if (!access || !refresh) {
    // If no tokens, no need to add Authorization header
    return req;
  }

  try {
    const user = jwtDecode(access);
    const isExpired = dayjs.unix(user.exp).diff(dayjs()) < 1;
    
    if (!isExpired) {
      req.headers.Authorization = `Bearer ${access}`;
      return req;
    }


    const res = await axios.post(`${baseURL}auth/token/refresh/`, {
      refresh: refresh,
    });

    const newAccess = res.data.access;
    console.log('New access token:', newAccess);

    // Store new access token in localStorage
    localStorage.setItem("access",newAccess);
    req.headers.Authorization = `Bearer ${newAccess}`;

    return req;
  } catch (error) {
    // If refresh fails, attempt to logout the user
    console.error("Token refresh failed:", error);
    try {
      const logoutRes = await axios.post(`${baseURL}auth/logout/`, { refresh: refresh });

      if (logoutRes.status === 200 || logoutRes.status === 200) {
        console.log('succeessfully logged out');
        
      }else{
        console.error('logout failed with sttus',logoutRes.status);
        
      }
    } catch (logoutError) {
      console.error("Logout failed:", logoutError);
    }

    // Clear stored tokens and user data
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    localStorage.removeItem("user");

    // Optionally, redirect to login
    window.location.href = '/login';

    return Promise.reject(err);  // Ensure the request still proceeds
  }
},
(error) =>{
  return Promise.reject(error)
}
);

export default axiosInstance;
