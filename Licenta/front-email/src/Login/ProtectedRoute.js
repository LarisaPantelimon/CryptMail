import React, { useContext } from 'react';
import { Navigate } from 'react-router-dom';
import { AuthContext } from './AuthContext';

const ProtectedRoute = ({ children, adminOnly = false }) => {
  const { isAuthenticated, isAdmin, isLoading } = useContext(AuthContext);

  //console.log('ProtectedRoute: ', { isLoading, isAuthenticated, isAdmin, adminOnly });

  if (isLoading) {
    //console.log('ProtectedRoute: Rendering loading state');
    return <div>Loading...</div>;
  }

  if (isAuthenticated === false) {
    //console.log('ProtectedRoute: Redirecting to /login (not authenticated)');
    return <Navigate to="/login" replace />;
  }

  if (adminOnly && !isAdmin) {
    //console.log('ProtectedRoute: Redirecting to /not-found (adminOnly true, isAdmin false)');
    return <Navigate to="/not-found" replace />;
  }

  //console.log('ProtectedRoute: Rendering children');
  return children;
};

export default ProtectedRoute;