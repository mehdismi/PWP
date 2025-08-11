import React, { createContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axiosInstance from '../api/axiosInstance';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loadingUser, setLoadingUser] = useState(true); 
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      fetchUser();
    } else {
      setLoadingUser(false);
    }
  }, []);

  const fetchUser = async () => {
    try {
      const access_token = localStorage.getItem('access_token');
      if (!access_token) return;

      const tokenPayload = JSON.parse(atob(access_token.split('.')[1]));
      const userId = tokenPayload.user_id;

      const response = await axiosInstance.get(`accounts/profile/${userId}/`);

      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user:', error);
      logout(false);
    } finally {
      setTimeout(() => {
        setLoadingUser(false);
      }, 500);
    }
  };

  const login = async (access, refresh) => {
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
    await fetchUser();
  };

  const logout = (redirect = true) => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setUser(null);
    if (redirect) {
      navigate('/login');
    }
  };

  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated, loadingUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
