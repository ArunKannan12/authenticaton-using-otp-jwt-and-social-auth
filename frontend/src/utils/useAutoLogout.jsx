// useAutoLogout.js
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { refreshAccessToken } from './refreshAccessToken';
import { jwtDecode } from 'jwt-decode';

const INACTIVITY_LIMIT = 30 * 1000;
const MODAL_COUNTDOWN = 10 * 1000;

const useAutoLogout = () => {
  const navigate = useNavigate();
  const inactivityTimerId = useRef(null);
  const expiryCheckTimerId = useRef(null);
  const countdownTimerId = useRef(null);

  const [modalOpen, setModalOpen] = useState(false);

  const logout = () => {
    clearTimeout(inactivityTimerId.current);
    clearTimeout(expiryCheckTimerId.current);
    clearTimeout(countdownTimerId.current);

    localStorage.clear();
    toast.info('Session expired due to inactivity.');
    setModalOpen(false);
    navigate('/login');
  };

  const startLogoutCountdown = () => {
    setModalOpen(true);
    countdownTimerId.current = setTimeout(() => {
      logout();
    }, MODAL_COUNTDOWN);
  };

  const resetInactivityTimer = () => {
    clearTimeout(inactivityTimerId.current);
    clearTimeout(countdownTimerId.current);
    setModalOpen(false);
    inactivityTimerId.current = setTimeout(() => {
      startLogoutCountdown();
    }, INACTIVITY_LIMIT);
  };

  const handleActivity = () => {
    resetInactivityTimer();
  };

  const setupTokenExpiryCheck = async () => {
    let accessToken = localStorage.getItem('access');
    const refreshToken = localStorage.getItem('refresh');

    if (!refreshToken) {
      logout();
      return;
    }

    try {
      if (!accessToken) {
        accessToken = await refreshAccessToken();
        if (!accessToken) return logout();
      }

      const { exp } = jwtDecode(accessToken);
      const expiryTime = exp * 1000;
      const now = Date.now();
      const timeUntilExpiry = expiryTime - now;

      if (timeUntilExpiry <= 0) {
        const newToken = await refreshAccessToken();
        if (!newToken) return logout();
        setupTokenExpiryCheck();
      } else {
        expiryCheckTimerId.current = setTimeout(async () => {
          const refreshed = await refreshAccessToken();
          if (!refreshed) return logout();
          setupTokenExpiryCheck();
        }, timeUntilExpiry - 1000);
      }
    } catch (err) {
      console.error('Token decode failed', err);
      logout();
    }
  };

  useEffect(() => {
    const events = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((event) => window.addEventListener(event, handleActivity));

    resetInactivityTimer();
    setupTokenExpiryCheck();

    return () => {
      events.forEach((event) => window.removeEventListener(event, handleActivity));
      clearTimeout(inactivityTimerId.current);
      clearTimeout(expiryCheckTimerId.current);
      clearTimeout(countdownTimerId.current);
    };
  }, []);

  return {
    modalOpen,
    onConfirm: resetInactivityTimer,
    onClose: logout,
  };
};

export default useAutoLogout;
