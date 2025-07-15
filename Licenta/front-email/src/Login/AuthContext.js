// src/context/AuthContext.js
import React, { createContext, useState, useEffect } from 'react';
import apiFetch from './api';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const [isAdmin, setIsAdmin] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  const handleAuthFailure = () => {
    setIsAuthenticated(false);
    setIsAdmin(false);
  };

  useEffect(() => {
    let isMounted = true;

    const checkAuth = async () => {
      try {
        const response = await apiFetch('/api/check-auth', {
          method: 'GET',
        });

        const data = await response.json();
        if (isMounted) {
          if (response.ok) {
            setIsAuthenticated(data.authenticated || false);
            setIsAdmin(data.isAdmin || false);
          } else {
            setIsAuthenticated(false);
            setIsAdmin(false);
          }
        }
      } catch (error) {
        //console.error('Error checking authentication:', error);
        if (isMounted) {
          setIsAuthenticated(false);
          setIsAdmin(false);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    checkAuth();

    return () => {
      isMounted = false;
    };
  }, []);

  const login = async (credentials) => {
    try {
      const response = await apiFetch('/api/login', {
        method: 'POST',
        body: JSON.stringify(credentials),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      setIsAuthenticated(true);
      setIsAdmin(data.isAdmin || false);
      return data.two_factor;
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      const response = await apiFetch('/api/logout', {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Logout failed');
      }

      setIsAuthenticated(false);
      setIsAdmin(false);
      window.location.href = '/login';
    } catch (error) {
      //console.error('Logout error:', error);
      setIsAuthenticated(false);
      setIsAdmin(false);
      window.location.href = '/login';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        setIsAuthenticated,
        isAdmin,
        setIsAdmin,
        isLoading,
        login,
        logout,
        fetchWithAuth: (url, options = {}) =>
          apiFetch(url, { ...options, onAuthFailure: handleAuthFailure }),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};