import React, { useState } from 'react';
import "./Register.css";
import { QRCodeCanvas } from "qrcode.react";
import DOMPurify from 'dompurify';
import logo from '../ImgSrc/image-Photoroom.png';// Adjust path if logo is elsewhere
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import {
  encryptWithPassword,
  hashPassword,
  generateRsaKeyPairWorker,
} from '../EncDecFunctions/EncDecFunctions.js';

function Register() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    fullName: '',
    phoneNumber: '',
    gender: '',
    birthday: '',
    privateKeyPem: '',
    publicKeyPem: '',
    twoFactorAuth: false,
  });
  const [showQR, setShowQR] = useState(false);
  const [is2FAConfirmed, setIs2FAConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const isValidEmail = (email) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email) && email.toLowerCase().endsWith('@cryptmail.ro');
  };

  const isValidPhoneNumber = (phone) => {
    const phoneRegex = /^\d{10}$/;
    return phoneRegex.test(phone);
  };

  const isValidFullName = (name) => {
    const nameRegex = /^[a-zA-Z\s'-]{1,100}$/;
    return nameRegex.test(name);
  };

  const isValidPassword = (password) => {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;
    return passwordRegex.test(password);
  };

  const isValidBirthday = (birthday) => {
    const date = new Date(birthday);
    const today = new Date();
    const minDate = new Date('1900-01-01');
    return date instanceof Date && !isNaN(date) && date >= minDate && date <= today;
  };

  const validateInputs = () => {
    const trimmedData = {
      email: formData.email.trim(),
      password: formData.password.trim(),
      fullName: formData.fullName.trim(),
      phoneNumber: formData.phoneNumber.trim(),
      gender: formData.gender,
      birthday: formData.birthday,
    };

    if (!trimmedData.email || !trimmedData.password || !trimmedData.fullName ||
        !trimmedData.phoneNumber || !trimmedData.gender || !trimmedData.birthday) {
      return { valid: false, error: 'All fields are required.' };
    }

    if (!isValidEmail(trimmedData.email)) {
      return { valid: false, error: 'Email must be a valid @cryptmail.ro address.' };
    }

    if (trimmedData.email.length > 255) {
      return { valid: false, error: 'Email is too long (max 255 characters).' };
    }

    if (!isValidPassword(trimmedData.password)) {
      return { valid: false, error: 'Password must be 8-128 characters, including uppercase, lowercase, number, and special character.' };
    }

    if (!isValidFullName(trimmedData.fullName)) {
      return { valid: false, error: 'Full name must contain only letters, spaces, hyphens, or apostrophes (max 100 characters).' };
    }

    if (!isValidPhoneNumber(trimmedData.phoneNumber)) {
      return { valid: false, error: 'Phone number must be a valid format (e.g., +1234567890 or 123-456-7890).' };
    }

    if (!['male', 'female', 'other'].includes(trimmedData.gender)) {
      return { valid: false, error: 'Please select a valid gender.' };
    }

    if (!isValidBirthday(trimmedData.birthday)) {
      return { valid: false, error: 'Birthday must be a valid date between 1900 and today.' };
    }

    return { valid: true, trimmedData };
  };

  const handleChange = (e) => {
    const { name, type, checked, value } = e.target;
    
    setFormData((prevData) => ({
      ...prevData,
      [name]: type === "checkbox" ? checked : value,
    }));
    setError('');
  };

  const HandleSignIn = async () => {
    try {
      //console.log("We're in");
      setLoading(true);
      setError('');
      toast.warning("Do not press the button again! Please wait while we process your request...");

      const { valid, error, trimmedData } = validateInputs();
      if (!valid) {
        setError(error);
        // setLoading(false);
        return;
      }

      let updatedFormData = { ...formData, ...trimmedData };

      if (!updatedFormData.publicKeyPem) {
        //console.log("Generating RSA key pair...");
        const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairWorker();
        //console.log("Encrypting private key...");
        const encryptedPrivateKey = encryptWithPassword(privateKeyPem, updatedFormData.password);
       
        updatedFormData.privateKeyPem = encryptedPrivateKey;
        updatedFormData.publicKeyPem = publicKeyPem;
        formData.publicKeyPem=publicKeyPem;
        formData.privateKeyPem=encryptedPrivateKey;
        setLoading(false);
  
        if (updatedFormData.twoFactorAuth && !is2FAConfirmed && updatedFormData.publicKeyPem) {
          setShowQR(true);
          setLoading(false);
          return;
        }
      }

      //console.log("Encrypting password...");
      updatedFormData.password = await hashPassword(updatedFormData.password);

      const csrfToken = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrf_access_token='))
        ?.split('=')[1];

      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': csrfToken || '',
        },
        credentials: 'include',
        body: JSON.stringify(updatedFormData),
      });

      if (response.ok) {
        window.location.href = '/Login';
      } else {
        const data = await response.json();
        toast.error(DOMPurify.sanitize('The user already exists' || 'Registration failed. Please try again.'));
      }
    } catch (error) {
      //console.error("Error:", error);
      toast.error(DOMPurify.sanitize(error.message || 'An error occurred during registration.'));
    } finally {
      // setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    setLoading(true);
    e.preventDefault();
    setLoading(true);
    HandleSignIn();
  };

  return (
    <div className="register-page">
      <div className="register-container">
        <h2 className="register-title">Register</h2>
        <form onSubmit={handleSubmit} className="register-form">
          <div className="row">
            <div className="input-group">
              <label>Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                maxLength={255}
                disabled={loading}
              />
            </div>
            <div className="input-group">
              <label>Phone Number</label>
              <input
                type="text"
                name="phoneNumber"
                value={formData.phoneNumber}
                onChange={handleChange}
                required
                maxLength={15}
                disabled={loading}
              />
            </div>
          </div>

          <div className="row">
            <div className="input-group">
              <label>Password</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                maxLength={128}
                disabled={loading}
              />
            </div>
            <div className="input-group-gender">
              <label>Gender</label>
              <select
                name="gender"
                value={formData.gender}
                onChange={handleChange}
                required
                disabled={loading}
              >
                <option value="">Select gender</option>
                <option value="male">Male</option>
                <option value="female">Female</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>

          <div className="row">
            <div className="input-group">
              <label>Full Name</label>
              <input
                type="text"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                required
                maxLength={100}
                disabled={loading}
              />
            </div>
            <div className="input-group">
              <label>Birthday</label>
              <input
                type="date"
                name="birthday"
                value={formData.birthday}
                onChange={handleChange}
                required
                disabled={loading}
              />
            </div>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="twoFactorAuth"
              name="twoFactorAuth"
              checked={formData.twoFactorAuth}
              onChange={handleChange}
              disabled={loading}
            />
            <label htmlFor="twoFactorAuth">
              Two-factor authentication? You will have to install CryptMail Authenticator
            </label>
          </div>

          {error && <p className="error-message" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(error) }} />}

          <button type="submit" className="register-button" disabled={loading}>
            {loading ? (
              <>
                <span className="spinner"></span> Register...
              </>
            ) : (
              'Register'
            )}
          </button>
        </form>
      </div>
      <div className="logo-container">
        <img src={logo} alt="CryptMail Logo" className="logo-image" />
      </div>

      {showQR && (
        <div className="qr-modal">
          <div className="qr-content">
            <div className="modal-content-qr">
              <h3>Scan this QR code to enable 2FA</h3>
              <QRCodeCanvas 
                value={JSON.stringify({
                  email: formData.email,
                  publicKey: formData.publicKeyPem.replace(/\n/g, "\\n")
                })} 
              />
              <button onClick={() => {
                setShowQR(false);
                setIs2FAConfirmed(true);
                HandleSignIn();
              }}>
                Confirm & Continue
              </button>
            </div>
          </div>
        </div>
      )}
    <ToastContainer
      position="top-center"
      className="custom-toast-container"
      toastClassName="custom-toast"
      bodyClassName="custom-toast-body"
  />
    </div>
  );
}

export default Register;