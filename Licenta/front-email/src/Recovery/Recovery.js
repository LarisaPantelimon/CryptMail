import React, { useState, useEffect, useCallback, useRef, useContext} from 'react';
import './Recovery.css';
import CryptoJS from 'crypto-js';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleExclamation } from '@fortawesome/free-solid-svg-icons';
import{
    encryptWithPasswordAsync,
    decryptWithPassword,
} from '../EncDecFunctions/EncDecFunctions'
import { useNavigate } from 'react-router-dom';
import { faInbox, faShieldAlt, faUser, faQuestionCircle, faBars } from '@fortawesome/free-solid-svg-icons';
import logo from '../ImgSrc/logoWhite.png';
import { AuthContext } from '../Login/AuthContext';

function Recovery() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const [recoveryEmail, setRecoveryEmail] = useState('');
    const [originalEmail, setOriginalEmail] = useState('');
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [verified, setVerified] = useState(false);
    const [generatedCode, setGeneratedCode] = useState('');
    const [verificationCode, setVerificationCode] = useState('');
    const [isVerificationPopupOpen, setVerificationPopupOpen] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [fileRecoveryExists,checkFileRecoveryExists]=useState(false);
    const [fileDepricated, setFileDepricated]=useState(false);
    const [showPasswordModal, setShowPasswordModal] = useState(false);
    const [showPasswordModal2, setShowPasswordModal2] = useState(false);
    const [currentPassword, setCurrentPassword] = useState('');
    const [showRecoveryModal, setRecoveryModal]=useState(false);
    const [recoveryLoading, setRecoveryLoading] = useState(false);
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);

    const[password, setPassword]=useState('');
    const [selectedFile, setSelectedFile]=useState('');
    const fileInputRef = useRef(null);

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    useEffect(() => {
        const fetchUserEmail = async () => {
            try {
                const response = await fetchWithAuth('/api/get-email', {
                    method: 'GET',
                    credentials: 'include'
                });
                const data = await response.json();
                if (response.ok) {
                    setEmail(data.email);
                } else {
                    setError(data.error);
                }
            } catch (error) {
                //console.error("Error:", error);
                setError("Failed to retrieve email. Please try again.");
            }
        };
        fetchUserEmail();
    }, []);

    const fetchPrivateKeys = async (oldEmail) => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-all-privatekeys', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email: oldEmail }),
            });
    
            if (!response.ok) {
                throw new Error("Failed to fetch private keys.");
            }
    
            const data = await response.json(); // Parse response as JSON
    
            const privateKeys = data.PrivateKeys.map(item => ({
                PrivateKey: item.PrivateKey,
                KeyId: item.KeyId,
            }));
    
            //console.log("Fetched private keys:", privateKeys);
            return privateKeys; // Return extracted private keys
        } catch (error) {
            //console.error("Error fetching private keys:", error);
            throw new Error("Failed to retrieve private keys. Please try again.");
        }
    };

    const VerifyRecoveryMode = useCallback(async () => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
          const response = await fetchWithAuth('/api/check-status', {
            method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
            body: JSON.stringify({ email }),
          });
          if (!response.ok) throw new Error("Failed to fetch recovery flag.");
          const data = await response.json();
          //console.log(data.Flag_Reset);
          setRecoveryModal(data.Flag_Reset);
        //setRecoveryModal(true);
        } catch (error) {
          //console.error("Error fetching recovery flag:", error);
        }
      }, [email]);

    const getRecoveryEmail = useCallback(async () => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-recovery-email', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email })
            });
            const data = await response.json();
            if (response.ok) {
                setVerified(data.verification || false);
                setRecoveryEmail(data.recovery_email || '');
                setOriginalEmail(data.recovery_email || '');
            }
        } catch (error) {
            //console.error("Error:", error);
            setError("Failed to retrieve recovery email.");
        }
    }, [email]);

    const CheckFileRecovery = useCallback(async () => {
        if (!email) {
            toast.error("Error: Email is missing.");
            setError("Email is required to check the recovery file.");  // Ensure setError exists in your state
            return;
        }
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/check-recovery-file', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email }),
                credentials: 'include'  // Required if using credentials in Flask CORS
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.status} ${response.statusText}`);
            }
    
            const data = await response.json();

            if (typeof data.exists !== "boolean") {
                throw new Error("Invalid response format: Missing 'exists' field");
            }
            checkFileRecoveryExists(true);
            if (data.exists) {
                setFileDepricated(!!data.fileUsed);
            }
        } catch (error) {
            toast.error("Error:", error);
            setError("Failed to check recovery file.");
        }
    }, [email]);
    
    useEffect(() => {
        const fetchData = async () => {
          if (email) {
            try {
              await Promise.all([
                getRecoveryEmail(),
                CheckFileRecovery(),
                VerifyRecoveryMode(),
              ]);
            } catch (error) {
              //console.error("Error in useEffect:", error);
            }
          }
        };
        fetchData();
      }, [email, getRecoveryEmail, CheckFileRecovery, VerifyRecoveryMode]);

    const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

    const handleSaveEmail = async () => {
        if (recoveryEmail === originalEmail) {
            //console.log("No changes detected, skipping update.");
            setIsEditing(false);
            return;
        }

        const endpoint = originalEmail ? 'update-recovery-email' : 'save-recovery-email';
        
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth(`/api/${endpoint}`, {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email, recovery_email: recoveryEmail })
            });
            if (!response.ok) {
                throw new Error("Failed to save email.");
            }
            setOriginalEmail(recoveryEmail);
            setVerified(false); // Reset verification on change
            setIsEditing(false);
            toast.success("Recovery email updated successfully.");
        } catch (error) {
            //console.error("Error:", error);
            toast.error("Failed to save email.");
        }
    };

    const handleVerifyEmail = async () => {
        if (!recoveryEmail) {
            toast.warning("You need to enter an email first!");
            return;
        }

        const code = generateCode();
        setGeneratedCode(code);
        setVerificationPopupOpen(true);

        try {
            const response = await fetchWithAuth('/api/verify-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: recoveryEmail, code })
            });
            if (!response.ok) {
                toast.error("Failed to send verification email.");
            }
            toast.success("Verification email sent! Please check your inbox.");
        } catch (error) {
            //console.error("Error:", error);
            toast.error("An error occurred while sending verification email.");
        }
    };

    const handleVerifyCode = async () => {
        if (verificationCode === generatedCode) {
            toast.success("Email verified successfully!");
            setVerificationPopupOpen(false);
            setVerified(true);

            const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
            try {
                const response = await fetchWithAuth('/api/marked-verified', {
                    method: 'POST',
                    credentials: 'include', // Sends access_token cookie
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                    },
                    body: JSON.stringify({ email })
                });
                if (!response.ok) {
                    toast.error("Failed to mark email as verified.");
                }
            } catch (error) {
                //console.error("Error:", error);
            }
        } else {
            toast.error("Invalid verification code. Try again.");
        }
    };

    function generateSecurePassword(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/`~';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        
        return Array.from(array, (num) => chars[num % chars.length]).join('');
    }

    async function encryptDataWithAES256GCM(data, password) {
        const encoder = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
    
        // Derive AES-GCM key from password using PBKDF2
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );
    
        // Convert data to JSON and encrypt
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoder.encode(JSON.stringify(data))
        );
    
        // Convert to Base64 for easy storage
        const encryptedObj = {
            salt: btoa(String.fromCharCode(...salt)),
            iv: btoa(String.fromCharCode(...iv)),
            data: btoa(String.fromCharCode(...new Uint8Array(encryptedData)))
        };
    
        return JSON.stringify(encryptedObj);
    }

    async function decryptDataWithAES256GCM(encryptedString, password) {
        const decoder = new TextDecoder();
        const encoder = new TextEncoder();

        const encryptedObj = JSON.parse(encryptedString);

        const salt = new Uint8Array(atob(encryptedObj.salt).split("").map(c => c.charCodeAt(0)));
        const iv = new Uint8Array(atob(encryptedObj.iv).split("").map(c => c.charCodeAt(0)));
        const encryptedData = new Uint8Array(atob(encryptedObj.data).split("").map(c => c.charCodeAt(0)));

        //console.log(salt);
        //console.log(iv);
        //console.log(encryptedData);
    
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
    
        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
    
        try {
            const decryptedData = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                encryptedData
            );
            return JSON.parse(decoder.decode(decryptedData)); // Convert back to object
        } catch (error) {
            //console.error("Decryption failed:", error);
            return null;
        }
    }
    

    function downloadFile(content, filename) {
        const blob = new Blob([content], { type: "application/json" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
 
    const GenerateRecoveryFile = async () => {
        setRecoveryLoading(true);
        try {
            const encryptedPrivateKeys = await fetchPrivateKeys(email);
            if (!encryptedPrivateKeys || encryptedPrivateKeys.length === 0) {
                toast.error('No private keys found to generate recovery file');
            }

            //console.log('Decrypting and re-encrypting private keys...');
            const sessionKey = await fetchSessionKey();
            const decryptedPassword = CryptoJS.AES.decrypt(
            sessionStorage.getItem('x7k9p2m'),
            sessionKey
            ).toString(CryptoJS.enc.Utf8);

            const decryptedPrivateKeys = [];
            const failedKeys = [];

            encryptedPrivateKeys.forEach((encryptedKeyObj) => {
            const encryptedKey = encryptedKeyObj.PrivateKey;
            const keyId = encryptedKeyObj.KeyId;
            ////console.log(`Processing key: ${keyId}`);

            try {
                const decryptedKey = decryptWithPassword(encryptedKey, decryptedPassword);
                if (decryptedKey !== null && decryptedKey !== undefined) 
                {decryptedPrivateKeys.push({
                KeyId: keyId,
                DecryptedKey: decryptedKey,
                });}
            } catch (error) {
                //console.error(`Failed to decrypt key ${keyId}:`, error);
                failedKeys.push(keyId);
            }
            });

            if (decryptedPrivateKeys.length === 0) {
            toast.error('No keys could be decrypted to generate recovery file');
            }

            const safePassword = generateSecurePassword();
            const encryptedContent = await encryptDataWithAES256GCM(decryptedPrivateKeys, safePassword);
            downloadFile(encryptedContent, 'recovery_file.json');

            const csrfToken = document.cookie
            .split('; ')
            .find((row) => row.startsWith('csrf_access_token='))
            ?.split('=')[1];

            const response = await fetchWithAuth('/api/generate-recovery-file', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken,
            },
            body: JSON.stringify({
                email: email,
                password: safePassword,
            }),
            });

            if (!response.ok) {
            throw new Error('Failed to save recovery file to server');
            }

            if (failedKeys.length > 0) {
            // console.log(
            //     `Recovery file generated with ${decryptedPrivateKeys.length} of ${
            //     encryptedPrivateKeys.length
            //     } keys. Failed to decrypt key(s): ${failedKeys.join(', ')}`
            // );
            } else {
            toast.success('Recovery file generated successfully with all keys');
            }
        } catch (error) {
            //console.error('Error generating recovery file:', error);
            toast.error(error.message || 'Failed to generate recovery file. Please try again.');
        } finally {
            setRecoveryLoading(false);
        }
        };

    const fetchSessionKeyRecovery=async()=>{
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try{
            const response = await fetchWithAuth('/api/get-key-for-recovery', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({
                    email: email
                }),
            });
            if(response.ok)
            {
                const data = await response.json();
                return data.key;
            }
            else{
                toast.error("You don't have a recovery file or is deprecated!");
            }
        }
        catch (error) {
            //console.error("Error adding the recovery file:", error);
            setError("Failed to add the recovery file. Please try again.");
        }
    }

    const SendReencKeys=async(email, rencKeys)=>{
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try{
            const response = await fetchWithAuth('/api/recover-all-keys', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({
                    email: email,
                    rencKeys: rencKeys
                }),
            });
            if(response.ok)
            {
                toast.success("Keys are up to date!");
            }
        }
        catch (error) {
            //console.error("Error adding the recovery file:", error);
            setError("Failed to add the recovery file. Please try again.");
        }
    }

    const fetchSessionKey = async () => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-session-key', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                }
            });

            if (!response.ok) {
                throw new Error("Failed to fetch session key.");
            }

            const { sessionKey } = await response.json();
            return sessionKey;
        } catch (error) {
            //console.error("Error fetching session key:", error);
            throw new Error("Failed to retrieve session key. Please try again.");
        }
    };

    const handleFileUpload = async (file) => {
        const sessionKeyRecovery = await fetchSessionKeyRecovery();
        
        if (file) {
            const reader = new FileReader();
            reader.onload = async (e) => {
                const fileContent = e.target.result;
                const decryptedData = await decryptDataWithAES256GCM(fileContent, sessionKeyRecovery);
                if(decryptedData===null)
                    {
                        toast.error("Your recovery file is outdated!");
                        return;
                    }
                
                //console.log("Decrypted data: ", decryptedData);
                //i should get my own password
                const sessionKey= await fetchSessionKey();
                const decryptedPassword = CryptoJS.AES.decrypt(sessionStorage.getItem('x7k9p2m'), sessionKey).toString(CryptoJS.enc.Utf8);
        
                if (Array.isArray(decryptedData)) {
                    const reEncryptedData = await Promise.all(
                        decryptedData.map(async (item) => {
                            const encryptedKey = await encryptWithPasswordAsync(item.DecryptedKey, decryptedPassword); // Encrypt only the DecryptedKey
                            return {
                                KeyId: item.KeyId, 
                                EncryptedKey: encryptedKey
                            };
                        })
                    );
        
                    //console.log("Re-Encrypted Data:", reEncryptedData);
                    SendReencKeys(email,reEncryptedData);
                } else {
                    //console.error("Decrypted data is not an array!");
                }
            };
            reader.readAsText(file);
        }
        
    };

    return (
        <div className="MyRecoverPage">
            <h1 className="page-new-title">Account and Data Recovery</h1>
            {/* Toggle Button */}
            <button
                className={`account-sidebar-toggle ${isSidebarOpen ? 'active' : ''}`}
                onClick={(e) => {
                    e.stopPropagation();
                    //console.log('Toggle button clicked');
                    toggleSidebar();
                }}
                aria-label="Toggle sidebar"
            >
                <FontAwesomeIcon icon={faBars} />
            </button>
    
            {/* Sidebar */}
            <div className={`account-sidebar ${isSidebarOpen ? 'open' : ''}`}>
                <div className="account-sidebar-header">
                    <div className="account-sidebar-logo">
                        <img src={logo} alt="CryptMail Logo" />
                    </div>
                </div>
                <ul className="account-sidebar-menu">
                    <li>
                        <button
                            className="account-sidebar-button"
                            onClick={() => {
                                navigate('/Inbox');
                                setIsSidebarOpen(false);
                            }}
                            title="Inbox"
                            aria-label="Navigate to Inbox"
                        >
                            <FontAwesomeIcon icon={faInbox} className="account-sidebar-icon" />
                            <span className="account-sidebar-text">Inbox</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="account-sidebar-button"
                            onClick={() => {
                                navigate('/Account');
                                setIsSidebarOpen(false);
                            }}
                            title="Account Settings"
                            aria-label="Navigate to Account Settings"
                        >
                            <FontAwesomeIcon icon={faUser} className="account-sidebar-icon" />
                            <span className="account-sidebar-text">Account Settings</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="account-sidebar-button active"
                            onClick={() => {
                                navigate('/Recovery');
                                setIsSidebarOpen(false);
                            }}
                            title="Recovery Data"
                            aria-label="Navigate to Recovery Data"
                        >
                            <FontAwesomeIcon icon={faShieldAlt} className="account-sidebar-icon" />
                            <span className="account-sidebar-text">Recovery Data</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="account-sidebar-button"
                            onClick={() => {
                                navigate('/info');
                                setIsSidebarOpen(false);
                            }}
                            title="Info Page"
                            aria-label="Navigate to Info Page"
                        >
                            <FontAwesomeIcon icon={faQuestionCircle} className="account-sidebar-icon" />
                            <span className="account-sidebar-text">Info Page</span>
                        </button>
                    </li>
                </ul>
            </div>
            {showRecoveryModal && (
            <div className="RecoverYourEmails">
                <h3 card-title-new>Recover Your Data</h3>
                <p className="recoveryText2">
                    <FontAwesomeIcon icon={faCircleExclamation} className="icon" />
                    <span>
                    Please upload your recovery file if you've generated one. Without it, you'll lose access to all previous messages!
                    </span>
                </p>
                <div className="file-upload-wrapper">
                <label htmlFor="recoveryFile" className="uploadButton">
                    Upload Recovery File
                </label>
                <input
                        type="file"
                        id="recoveryFile"
                        accept=".json, .txt"
                        ref={fileInputRef} // Add a ref to the input
                        onChange={(e) => {
                            setSelectedFile(e.target.files[0]);
                            handleFileUpload(e.target.files[0]);
                        }}
                        className="recoveryFileInput"
                        style={{ display: 'none' }}
                    />
                </div>
                <ToastContainer
                position="top-center"
                className="custom-toast-container"
                toastClassName="custom-toast"
                bodyClassName="custom-toast-body"
                />
            </div>
            )}
            {/* {showPasswordModal2 && (
            <div className="PasswordModal2">
                <div className="modal-content">
                    <span 
                        className="close-modal-password"
                        onClick={() => {
                            setShowPasswordModal2(false);
                            setPassword('');
                            setSelectedFile(null);
                            fileInputRef.current.value = '';
                        }}
                    >
                        �
                    </span>
                    <h3>Enter Password</h3>
                    <p className="passwordText">
                        <FontAwesomeIcon icon={faCircleExclamation} className="icon" />
                        <span>Please enter password to process recovery file</span>
                    </p>
                    <div className="password-input-wrapper">
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter password"
                            className="passwordInput"
                        />
                    </div>
                    <div className="modal-buttons2">
                        <button 
                            onClick={() => handleFileUpload(selectedFile, password)}
                        >
                            Process File
                        </button>
                    </div>
                </div>
            </div>
        )} */}
            <div className="EmailResetPassword">
            <h3 className="card-title-new">Account Recovery</h3>
            <div className="InsideEmailRec">
                <p className="textrec">Recovery Email Address:</p>
                <div className="inputContainer">
                    <i className="fas fa-envelope"></i>
                    <input
                        className="inputEmail"
                        type="text"
                        placeholder="Enter recovery email"
                        value={recoveryEmail}
                        onChange={(e) => {
                            setRecoveryEmail(e.target.value);
                            setVerified(false);
                        }}
                        disabled={!isEditing}
                    />
                    {!isEditing && (
                        <button className="EditButton" onClick={() => setIsEditing(true)}>
                            Edit
                        </button>
                    )}
                </div>
            </div>

            {/* Verification message above the Save button */}
            {recoveryEmail && (
                <div className="verificationSection">
                    <p className={`verifyMessage ${verified ? 'success' : 'error'}`}>
                        {verified ? '✅ Email address has been verified.' : '⚠️ Please verify your email.'}
                        {!verified && (
                            <button className="VerifyLink" onClick={handleVerifyEmail}>
                                Verify
                            </button>
                        )}
                    </p>
                </div>
            )}

            {isEditing && (
                <button
                    className="SaveButton"
                    onClick={handleSaveEmail}
                    disabled={recoveryEmail === originalEmail}
                >
                    Save
                </button>
            )}

            {isVerificationPopupOpen && (
                <div className="modal-verification">
                    <div className="modal-content-verification">
                        <h3>Check your inbox and enter the verification code</h3>
                        <input
                            type="text"
                            placeholder="Enter code"
                            value={verificationCode}
                            onChange={(e) => setVerificationCode(e.target.value)}
                        />
                        <div className="modal-buttons-verification">
                            <button className="modalbuttonsver" onClick={handleVerifyCode}>Verify</button>
                            <button  className="modalbuttonsver" onClick={() => setVerificationPopupOpen(false)}>Cancel</button>
                        </div>
                    </div>
                </div>
            )}
        </div>


            <div className="DataRecovery">
            <h3 className="card-title-new">Generate a Recovery File</h3>
            <p className="recoveryText">
                If you forget your password, after resetting it you will lose access to all your messages. 
                To avoid this, we recommend generating a recovery file so you can securely restore access to your emails.
            </p>
            <button  
                className={`RecoveryFileButton ${recoveryLoading ? 'loading' : ''}`}
                onClick={GenerateRecoveryFile}
                disabled={recoveryLoading}
            >{recoveryLoading ? 'Loading...' : 'Generate Recovery File'}</button>

            {/* Conditional messages */}
            {!fileRecoveryExists && <p className="error">
                                    <FontAwesomeIcon icon={faCircleExclamation} /> The user does not have a recovery file.
                                    </p>}
            {fileRecoveryExists && (
                <p className={fileDepricated ? "error" : "success"}>
                <FontAwesomeIcon icon={faCircleExclamation} /> 
                {fileDepricated ? " The file is no longer useful as it was used." : " The file is OK and can still be used."}
            </p>
            )}
        </div>
        {/* {showPasswordModal &&(
        <div className="PasswordModal">
            <div className="modal-content">
                <span className="close-modal-password" onClick={()=> setShowPasswordModal(false)}>&times;</span>
                <h2>Enter Password</h2>
                <input
                    type="password"
                    name="password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Password"
                    className="passwordmodalinput"
                />
                <button className="applybuttonpasswordmodel2" onClick={GenerateRecoveryFile}>Generate Recovery File</button>
            </div>
        </div>
        )} */}
    </div>
    );
}

export default Recovery;
