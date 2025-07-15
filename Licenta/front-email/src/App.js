import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import React from 'react';
import Login from './Login/Login';
import './App.css';
import Inbox from "./Inbox/Inbox";
import Register from "./Register/Register";
import { AuthProvider } from './Login/AuthContext';
import ProtectedRoute from './Login/ProtectedRoute';
import Account from './Account/Account';
import Recovery from "./Recovery/Recovery";
import ForgotPassword from "./ForgotPassword/forgotPassword";
import WelcomePage from "./WelcomePage/WelcomePage";
import Info from "./Info/InfoPage";
import AdminPannel from "./AdminPannel/AdminPannel";
import NotFound from "./NotFound/NotFound";

function App() {
  return (
    <AuthProvider>
      <div className="app">
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<WelcomePage />} />
            <Route path="/Login" element={<Login />} />
            <Route path="/Register" element={<Register />} />
            <Route path="/ForgotPassword" element={<ForgotPassword />} />
            <Route path="/WelcomePage" element={<WelcomePage />} />
            <Route path="/NotFound" element={<NotFound />} />

            {/* Protected routes */}
            <Route
              path="/Inbox"
              element={
                <ProtectedRoute>
                  <Inbox />
                </ProtectedRoute>
              }
            />
            <Route
              path="/Account"
              element={
                <ProtectedRoute>
                  <Account />
                </ProtectedRoute>
              }
            />
            <Route
              path="/Recovery"
              element={
                <ProtectedRoute>
                  <Recovery />
                </ProtectedRoute>
              }
            />
            <Route
              path="/Info"
              element={
                <ProtectedRoute>
                  <Info />
                </ProtectedRoute>
              }
            />
            <Route
              path="/AdminPannel"
              element={
                <ProtectedRoute adminOnly={true}>
                  <AdminPannel />
                </ProtectedRoute>
              }
            />

            {/* Catch-all route */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </div>
    </AuthProvider>
  );
}

export default App;