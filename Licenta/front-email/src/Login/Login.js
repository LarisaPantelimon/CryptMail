import React, { useState, useContext } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from './AuthContext';
import CryptoJS from 'crypto-js';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import DOMPurify from 'dompurify'; // Import DOMPurify for sanitizing error messages
import './Login.css';
import logo from '../ImgSrc/logo2.png';
import apiFetch from './api';
import { decryptWithPassword } from '../EncDecFunctions/EncDecFunctions.js';
import { bytesToHex, signHashforLogin } from '../Compose_Email/encryption';
import { encryptChallenges, handleZKPResponse } from '../Register/Homomorphic.js';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useContext(AuthContext); // Use the login function
  const navigate = useNavigate();

  // Email validation function
  const isValidEmail = (email) => {
    // Basic email format regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    // Check if email ends with @cryptmail.ro
    return emailRegex.test(email) && email.toLowerCase().endsWith('@cryptmail.ro');
  };

  // Input validation function
  const validateInputs = () => {
    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedEmail || !trimmedPassword) {
      toast.error('Email and password are required.');
      return false;
    }

    if (trimmedEmail.length > 255) {
      toast.error('Email is too long (max 255 characters).');
      return false;
    }

    if (!isValidEmail(trimmedEmail)) {
      toast.error('Email must be a valid @cryptmail.ro address.');
      return false;
    }

    if (trimmedPassword.length < 8 || trimmedPassword.length > 128) {
      toast.error('Password must be between 8 and 128 characters.');
      return false;
    }

    return { trimmedEmail, trimmedPassword };
  };

  const fetchSessionKey = async () => {
    const csrfToken = document.cookie
      .split('; ')
      .find(row => row.startsWith('csrf_access_token='))
      ?.split('=')[1];
	//console.log(csrfToken);
	//console.log(document.cookie.split("; ").find(row => row.startsWith("csrf_access_token=")));
    try {
        const response = await fetch('/api/get-session-key', {
        method: 'POST',
        credentials: 'include', // Sends access_token cookie
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': csrfToken, // Include CSRF token
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch session key.');
      }

      const { sessionKey } = await response.json();
      return sessionKey;
    } catch (error) {
      toast.error('Error fetching session key: ' + error.message);
      throw error;
    }
  };

  const fetch2FAInfo = async () => {
    try {
      const csrfToken = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrf_access_token='))
        ?.split('=')[1];
      //console.log("CSRF Token:", csrfToken);

      const response = await fetch('/api/get-2fa-info', {
        method: 'POST',
        credentials: 'include', // Sends access_token cookie
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': csrfToken, // Include CSRF token
        }
      });

      if (!response.ok) {
        toast.error('Failed to fetch 2FA info.');
      }

      const data = await response.json();
      return { PublicKey: data.PublicKey, PrivateKey: data.PrivateKey, PublicKeyMobile: data.PublicKeyMobile };
    } catch (error) {
      toast.error('Error fetching 2FA info: ' + error.message);
      throw error;
    }
  };

  const SendDataToMobile = async (randomString, signedHash, encM, c) => {
    try {
      const csrfToken = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrf_access_token='))
        ?.split('=')[1];
      const response = await fetch('/api/send-data-to-mobile', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': csrfToken,
        },
        body: JSON.stringify({ randomString, signedHash, encM, c }),
      });

      if (!response.ok) {
        //console.log(response);
        toast.error('Failed to send data to mobile.');
      }

      const data = await response.json();
      return data;
    } catch (error) {
      toast.error('Error sending data to mobile: ' + error.message);
      throw error;
    }
  };

  const handleLogin = async () => {
    setError('');
    setIsLoading(true);

    // Validate inputs
    const validated = validateInputs();
    if (!validated) {
      setIsLoading(false);
      return;
    }
    const { trimmedEmail, trimmedPassword } = validated;
//console.log("Am intrat in functie");

    try {
      // Step 1: Use the login function from AuthContext
      const twoFactor = await login({ email: trimmedEmail, password: trimmedPassword });
      //console.log("twoFactor", twoFactor);

      if (twoFactor) {
	//console.log("Prima e 2FA");
        const { PublicKey, PrivateKey, PublicKeyMobile } = await fetch2FAInfo();
	//console.log("Pub Key MOBILE: ",PublicKeyMobile);
        const decryptedPrivateKey = decryptWithPassword(PrivateKey, trimmedPassword);
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        const random_string = bytesToHex(randomBytes);
        const signedHash = await signHashforLogin(randomBytes, decryptedPrivateKey);
        const { encM, c, m } = encryptChallenges(PublicKey, PublicKeyMobile, trimmedEmail);
	//console.log("A doua e Session Key");
        const sessionKey = await fetchSessionKey();
        const response = await SendDataToMobile(random_string, signedHash, encM, c);
        const verify = handleZKPResponse(response, m, c, decryptedPrivateKey, PublicKeyMobile);
        //console.log("verify", verify);
        const result = await verify;
        if (result === true) {
          const encryptedPassword = CryptoJS.AES.encrypt(trimmedPassword, sessionKey).toString();
          sessionStorage.setItem('x7k9p2m', encryptedPassword);
          //alert('Login successful');
          navigate('/Inbox');
        } else {
          toast.error("Login failed. Please try again.");
        }
      } else {
        // Step 2: Fetch the session key after successful login
        const sessionKey = await fetchSessionKey();
        // Step 3: Encrypt password with session key
        const encryptedPassword = CryptoJS.AES.encrypt(trimmedPassword, sessionKey).toString();
        // Step 4: Store in sessionStorage
        sessionStorage.setItem('x7k9p2m', encryptedPassword);
        // Step 5: Navigate to Inbox
        //alert('Login successful');
        navigate('/Inbox');
      }
    } catch (error) {
      //console.error('Error:', error);
      // Sanitize error message before displaying
      const sanitizedError = DOMPurify.sanitize(error.message || 'The account does not exist or you have the wrong password.');
      // setError(sanitizedError);
      toast.error(sanitizedError);
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPassword = () => {
    // Validate email before navigating
    const trimmedEmail = email.trim();
    if (!trimmedEmail || !isValidEmail(trimmedEmail)) {
      toast.error('Please enter a valid @cryptmail.ro email address.');
      return;
    }
    navigate('/ForgotPassword', { state: { email: trimmedEmail } });
  };

  return (
    <div className="MyLoginPage">
      <div className="MyLoginCredentials">
        <div className="connect">
          <h1 className="SignInLogIn">Login/Sign Up</h1>
          <div className="ImageEmail">
            <i className="fas fa-envelope"></i>
            <input
              className="input1"
              type="text"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              maxLength={255} // Limit input length
              disabled={isLoading} // Disable during loading
            />
          </div>
          <div className="ImagePassword">
            <i className="fas fa-lock"></i>
            <input
              className="input1"
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={128} // Limit input length
              disabled={isLoading} // Disable during loading
            />
          </div>
          <button
            className="submitbutton"
            onClick={handleLogin}
            disabled={isLoading}
          >
            {isLoading ? 'LOGGING IN...' : 'SUBMIT'}
          </button>
        </div>
        {error && <p style={{ color: 'red' }} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(error) }} />}
        <div className="additionalinfo">
          <p>
            Forgot Password?{' '}
            <button className="linkforgot" onClick={handleForgotPassword}>
              Reset Password
            </button>
          </p>
        </div>
      </div>
      <div className="LogoPart">
        <img className="imagelogo" src={logo} alt="Logo" />
        <button className="registerButton">
          <a href="/Register">REGISTER</a>
        </button>
      </div>
      <ToastContainer
        position="top-center"
        className="custom-toast-container"
        toastClassName="custom-toast"
        bodyClassName="custom-toast-body"
      />
    </div>
  );
}

export default Login;