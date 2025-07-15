import React, { useState, useEffect, useContext } from 'react';
import './Account.css';
import CryptoJS from 'crypto-js'; 
import { faToggleOn, faToggleOff } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleExclamation } from '@fortawesome/free-solid-svg-icons';
import { faInfoCircle } from '@fortawesome/free-solid-svg-icons';
import { QRCodeCanvas } from "qrcode.react";
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useNavigate } from 'react-router-dom';
import { faInbox, faShieldAlt, faUser, faQuestionCircle, faBars } from '@fortawesome/free-solid-svg-icons';
import{
    encryptWithPassword,
    decryptWithPassword,
    hashPassword,
    generateRsaKeyPairWorker,
} from '../EncDecFunctions/EncDecFunctions.js';
import logo from '../ImgSrc/logoWhite.png';
import { AuthContext } from '../Login/AuthContext';

function Account() {
    const [user, setUser] = useState(null);
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isEditing, setIsEditing] = useState(false); 
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [enabled2FA, setEnabled2FA]=useState('');
    const [updatedUser, setUpdatedUser] = useState({
        FullName: '',
        Email: '',
        PhoneNumber: '',
        Gender: '',
        Birthday: '',
    });
    const [oldPassword, setOldPassword] = useState('');
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPasswordModal, setShowPasswordModal] = useState(false);
    const [showPasswordModalQR, setShowPasswordModalQR] = useState(false);
    const [isEnabled, setIsEnabled] = useState(false);
    const [publicKey,setPublicKey] = useState('');
    const [keyId, setKeyId] = useState(""); // Error message state
    const [newLoading, setNewLoading] = useState(false);
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);


    const isMatch = newPassword === confirmPassword && confirmPassword !== '';
    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };
    
    useEffect(() => {
        const fetchUserEmail = async () => {
            try {
                //console.log("Fetching user email...");
                const response = await fetchWithAuth('/api/get-email', {
                    method: 'GET',
                    credentials: 'include',
                });

                const data = await response.json();
                //console.log("Response data:", data);

                if (response.ok) {
                    const userEmail = data.email;
                    await fetchUserData(userEmail);
                    await fetchReceiverKey(userEmail);
                    await fetch2faState();
                } else {
                    setError(data.error);
                }
            } catch (error) {
                //console.error("Error:", error);
                setError("Failed to retrieve email. Please try again.");
            } finally {
                setLoading(false);
            }
        };

        fetchUserEmail();
    }, []);

    const fetch2faState= async ()=>{
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try{
            const response = await fetchWithAuth('/api/2fa-state',{
                method:'GET',
                credentials:'include',
                headers:{
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                }
            });
            const data = await response.json();
            if(response.ok)
                setEnabled2FA(data.get2fa);
            else
                toast.error("Unable to get 2FA state!");
        }
        catch (error) {
            //console.error("Error:", error);
            setError("Failed to retrieve user data. Please try again.");
        }
    }

    async function fetchUserData(userEmail) {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            //console.log("Fetching user data...");
            const response = await fetchWithAuth('/api/user', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email: userEmail }),
            });

            const data = await response.json();
            //console.log("Response data:", data);

            if (response.ok) {
                setUser(data.user); // Set user data to state
                setUpdatedUser({
                    FullName: data.user.FullName,
                    Email: data.user.Email,
                    PhoneNumber: data.user.PhoneNumber,
                    Gender: data.user.Gender,
                    Birthday: data.user.Birthday,
                }); 
            } else {
                setError(data.error);
            }
        } catch (error) {
            //console.error("Error:", error);
            setError("Failed to retrieve user data. Please try again.");
        }
    }

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setUpdatedUser((prevState) => ({
            ...prevState,
            [name]: value,
        }));
    };

    const handleSubmit = async (event) => {
        event.preventDefault(); 
    
        const updatedFields = {};
    
        if (user.FullName !== updatedUser.FullName) updatedFields.FullName = updatedUser.FullName;
        if (user.PhoneNumber !== updatedUser.PhoneNumber) updatedFields.PhoneNumber = updatedUser.PhoneNumber;
        if (user.Gender !== updatedUser.Gender) updatedFields.Gender = updatedUser.Gender;
        if (user.Birthday !== updatedUser.Birthday) updatedFields.Birthday = updatedUser.Birthday;
    
        if (Object.keys(updatedFields).length > 0) {
            const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
            try {
                const response = await fetchWithAuth('/api/update-user', {
                    method: 'POST',
                    credentials: 'include', // Sends access_token cookie
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                    },
                    body: JSON.stringify({
                        oldEmail: user.Email,  
                        updatedUser: updatedFields,  
                    }),
                });
    
                const data = await response.json();
                //console.log("Update response data:", data);
    
                if (response.ok) {
                    setUser({ ...user, ...updatedFields }); 
                    toast.success('Profile updated successfully');
                } else {
                    setError(data.error);
                }
            } catch (error) {
                //console.error("Error:", error);
                setError("Failed to update user data. Please try again.");
            }
        } else {
            alert("No changes detected");
        }
    };    

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

    async function updatePassword() {
        if (!isMatch) {
            alert("Passwords do not match");
            return;
        }
    
        try {
            //console.log("Fetching encrypted private keys...");
            //console.log(user.Email);
            const encryptedPrivateKeys = await fetchPrivateKeys(user.Email);
            ////console.log("Fetched Encrypted Private Keys:", encryptedPrivateKeys);

            //console.log("Decrypting and re-encrypting private keys...");
            const decryptedPrivateKeys = encryptedPrivateKeys.map(encryptedKeyObj => {
                // Extract the encrypted private key and KeyId
                const encryptedKey = encryptedKeyObj.PrivateKey;
                const keyId = encryptedKeyObj.KeyId;
                //console.log(encryptedKeyObj.PrivateKey);

                // Decrypt the private key using the old password
                const decryptedKey = decryptWithPassword(encryptedKey, oldPassword);

                // Return an object with the decrypted key and KeyId
                return {
                    KeyId: keyId,
                    DecryptedKey: decryptedKey
                };
            });

        //console.log("Decrypted private keys:");
        //console.log(decryptedPrivateKeys);

        const newEncryptedPrivateKeys = decryptedPrivateKeys.map(decryptedKeyObj => {
            // Extract the decrypted key and KeyId
            const decryptedKey = decryptedKeyObj.DecryptedKey;
            const keyId = decryptedKeyObj.KeyId;

        // Re-encrypt the private key using the new password
            const newEncryptedKey = encryptWithPassword(decryptedKey, newPassword);

            // Return an object with the re-encrypted key and KeyId
            return {
                KeyId: keyId,
                PrivateKey: newEncryptedKey
            };
        });

        //console.log("New encrypted private keys:");
        //console.log(newEncryptedPrivateKeys);
        //console.log(newEncryptedPrivateKeys[0]);
        const hashedPassword = await hashPassword(newPassword);

        //console.log("Updating password...");
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        const response = await fetchWithAuth('/api/update-password', {
            method: 'POST',
            credentials: 'include', // Sends access_token cookie
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken, // Include CSRF token
            },
            body: JSON.stringify({
                email: user.Email,
                oldPassword: oldPassword,
                newHashedPassword: hashedPassword,
                encryptedPrivateKeys: newEncryptedPrivateKeys, // Send the updated encrypted private keys
            }),
        });
        
        const data = await response.json();
        //console.log("Update password response data:", data);

        if (response.ok) {
            alert('Password updated successfully');
            const sessionKey = await fetchSessionKey();
            const EncryptedPassword = CryptoJS.AES.encrypt(newPassword, sessionKey).toString();
            sessionStorage.setItem('x7k9p2m', EncryptedPassword);
        } else {
            setError(data.error);
        }
        } catch (error) {
            //console.error("Error:", error);
            setError("Failed to update password. Please try again.");
        }
    }
        
    const fetchReceiverKey = async (receiverEmail) => {
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];
            try {
                const response = await fetchWithAuth('/api/get-last-key', {
                    method: 'POST',
                    credentials: 'include', // Sends access_token cookie
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                    },
                    body: JSON.stringify({ receiver_email: receiverEmail }),
                });
        
                const data = await response.json();
                if (response.ok) {
                    if(data.PublicKey===null)
                    {toast.error("Your Public Key is expired! Please generate a new one from the Profile Settings!"); return;}
                   setPublicKey(data.PublicKey);
                   setKeyId(data.KeyId);
                } else {
                    throw new Error(data.error || "Failed to fetch receiver's public key");
                }
            } catch (error) {
                //console.error("Error fetching receiver's public key:", error);
                throw error;
            }
        };
    const disable2FA=async()=>{
        const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];
            try {
                const response = await fetchWithAuth('/api/admin-disable-2fa', {
                    method: 'POST',
                    credentials: 'include', // Sends access_token cookie
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                    },
                    body: JSON.stringify(user.Email),
                });
                const data=await response.json();
                if(response.ok)
                    {setEnabled2FA(false);
                    toast.success("2FA disabled successfully!");}
                else
                    toast.error("Error: ",data.error);
            }
            catch(error){
                //console.error("Error diableing 2FA: ", error);
                throw error;
            }
    }
    async function AddNewKeyPair(){
        try {
            //console.log("Adding new key pair...");
            setNewLoading(true);
            const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairWorker();
            //trebuie sa imi decriptez parola inainte
            const sessionKey = await fetchSessionKey();
            //acum trebuie sa o decriptez
            const decryptedPassword = CryptoJS.AES.decrypt(sessionStorage.getItem('x7k9p2m'), sessionKey).toString(CryptoJS.enc.Utf8);
            //console.log("This is the password: ", decryptedPassword);  
            const encryptedPrivateKey = encryptWithPassword(privateKeyPem, decryptedPassword);
            // trebuie generata o noua pereche de chei
            // const keyPair = forge.pki.rsa.generateKeyPair({ bits: 4096 });
            const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
            const response = await fetchWithAuth('/api/generate-newkeys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                credentials: 'include',
                body: JSON.stringify({
                    email: user.Email,
                    publicKeyPem: publicKeyPem,
                    privateKeyPem: encryptedPrivateKey,
                }),
        });
            // const data = await response.json();
            if(response.ok)
            {
                toast.success('Key pair generated successfully');
            }

        }
        catch (error) {
            //console.error("Error adding new key pair:", error);

            toast.error("Failed to add new key pair. Please try again.");
        }
        // i will delete the file for recovery too
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try{
            const response = await fetchWithAuth('/api/delete-recovery-file', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({
                    email: user.Email,
                }),
        });
        if(response.ok)
            {
                setNewLoading(false);
                toast.success('Recovery file deleted successfully');
            }
        }
        catch (error) {
            setNewLoading(false);
            //console.error("Error deleting Recovery file:", error);
            toast.error("Failed to delete Recovery file. Please try again.");
        }
    }

    const update2FA = async () => {
        //const homomorphic = await generateAndEncryptKeys(currentPassword);
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/update-2fa', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({
                    email: user.Email
                }),
            });
    
            const data = await response.json();
            //console.log("Update 2FA response data:", data);
    
            if (response.ok) {
                setEnabled2FA(true);
                toast.success('Two Factor Authentication updated successfully');
            } else {
                toast.error(data.error);
            }
        }
        catch (error) {
            //console.error("Error:", error);
            toast.error("Failed to update Two Factor Authentication. Please try again.");
        }
    }

    return (
        <div className="user-profile">
            <h1 className="page-new-title">Account Settings</h1>
            {loading && <div>Loading...</div>}
            {error && <div>{error}</div>}
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
                            className="account-sidebar-button active"
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
                            className="account-sidebar-button"
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
            <div className="profile-container">
                {user && (
                    <div className="profile-card">
                        <h2 className="card-title-new">{isEditing ? 'Edit Profile' : 'Profile'}</h2>
    
                        <div className="profile-info">
                            <div>
                                <label className="mylabel">Full Name:</label>
                                {isEditing ? (
                                    <input
                                        type="text"
                                        name="FullName"
                                        value={updatedUser.FullName}
                                        onChange={handleInputChange}
                                    />
                                ) : (
                                    <p>{user.FullName}</p>
                                )}
                            </div>
    
                            <div>
                                <label className="mylabel">Email:</label>
                                <p>{user.Email}</p>  {/* Just display the email, no input field */}
                            </div>
    
                            <div>
                                <label className="mylabel">Phone:</label>
                                {isEditing ? (
                                    <input
                                        type="text"
                                        name="PhoneNumber"
                                        value={updatedUser.PhoneNumber}
                                        onChange={handleInputChange}
                                    />
                                ) : (
                                    <p>{user.PhoneNumber}</p>
                                )}
                            </div>
    
                            <div>
                                <label className="mylabel">Gender:</label>
                                {isEditing ? (
                                    <input
                                        type="text"
                                        name="Gender"
                                        value={updatedUser.Gender}
                                        onChange={handleInputChange}
                                    />
                                ) : (
                                    <p>{user.Gender}</p>
                                )}
                            </div>
    
                            <div>
                                <label className="mylabel">Birthday:</label>
                                {isEditing ? (
                                    <input
                                        type="date"
                                        name="Birthday"
                                        value={updatedUser.Birthday}
                                        onChange={handleInputChange}
                                    />
                                ) : (
                                    <p>{user.Birthday}</p>
                                )}
                            </div>
                        </div>
    
                        {/* Toggle between edit and view mode */}
                        {isEditing ? (
                            <button onClick={handleSubmit}>Save Changes</button>
                        ) : (
                            <button onClick={() => setIsEditing(true)}>Edit Profile</button>
                        )}
                    </div>
                    
                )}
                {/* Change Password Card */}
                <div className="column2">
                    <div className="password-card">
                        <h2 className="card-title-new">Change Password</h2>
                        <input
                            type="password"
                            name="oldPassword"
                            placeholder="Old Password"
                            value={oldPassword}
                            onChange={(e) => setOldPassword(e.target.value)}
                        />
                        <input
                            type="password"
                            name="newPassword"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            placeholder="New Password"
                        />
    
                        <input
                            type="password"
                            name="confirmPassword"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="Confirm New Password"
                            className={confirmPassword ? (isMatch ? 'match' : 'no-match') : ''}
                        />
    
                        <button onClick={() => updatePassword()}>Update Password</button>
                    </div>
    
                    {/* Generate Key Pair Card */}
                    <div className="key-card">
                        <h2 className="card-title-new">Generate New Key Pair</h2>
                        <p className='error'><FontAwesomeIcon icon={faCircleExclamation} /> When generating a new Key Pair you will have to generate a new Recovery File</p>
                        <button onClick={async () => {
                            try {
                                setNewLoading(true);
                                await AddNewKeyPair();
                            } catch (error) {
                                //console.error('Button click error:', error);
                                toast.error('Operation failed. Please try again.');
                            } finally {
                                setNewLoading(false); // Always reset loading state
                            }
                            }}
                        disabled={newLoading}
                        >
                        {newLoading ? 'Loading...' : 'Generate Key Pair'}
                        </button>
                    </div>
                    {/* {showPasswordModal && (
                        <div className="PasswordModal">
                            <div className="modal-content">
                                <span className="close-modal-password" onClick={() => setShowPasswordModal(false)}>�</span>
                                <h2>Enter Password</h2>
                                <input
                                    type="password"
                                    name="password"
                                    value={currentPassword}
                                    onChange={(e) => setCurrentPassword(e.target.value)}
                                    placeholder="Password"
                                    className="passwordmodalinput"
                                />
                                <button className="applybuttonpasswordmodel" onClick={async () => AddNewKeyPair()}>Generate Key Pair</button>
                            </div>
                        </div>
                    )} */}
                </div>
            </div>
            <div className="twofactor-container">
                <h2 className="card-title-new">Enable Two Factor Authentication</h2>
                <div className='twofactor-content'>
                    <p>Two-factor authentication adds an extra layer of security to your account.</p>
                    <div className="tooltip-container">
                        <FontAwesomeIcon icon={faInfoCircle} className="info-icon" />
                        <div className="tooltip-text">
                            Verify your identity with the CryptMail Authenticator app
                        </div>
                    </div>
                    <button
                        onClick={async() => {
                            if (enabled2FA === true) {
                                await disable2FA();
                            } else {
                                setIsEnabled(!isEnabled);
                            }
                        }}
                        className={`icon-toggle ${enabled2FA ? 'enabled' : ''}`}
                    >
                        <FontAwesomeIcon size="2x" icon={enabled2FA ? faToggleOn : faToggleOff} />
                    </button>
                </div>
                <div className='warning-2fa'>
                    <p className='error'><FontAwesomeIcon icon={faCircleExclamation} /> {" You can disable this at any moment!"}</p>
                </div>
            </div>
            {isEnabled && (
                <div className="qr-modal">
                    <div className="qr-content">
                        <div className="modal-content-qr">
                            <h3>Scan this QR code to enable 2FA</h3>
                            <QRCodeCanvas 
                                value={JSON.stringify({
                                    email: user.Email,
                                    publicKey: publicKey.replace(/\n/g, "\\n") // Escape newlines
                                })} 
                            />
                            <button onClick={() => {
                                update2FA();
                                setIsEnabled(!isEnabled);
                            }}>Confirm & Continue</button>
                        </div>
                    </div>
                </div>
            )}
            {/* {showPasswordModalQR && (
                <div className="PasswordModal">
                    <div className="modal-content">
                        <span className="close-modal-password" onClick={() => setShowPasswordModalQR(false)}>�</span>
                        <h2>Enter Password</h2>
                        <input
                            type="password"
                            name="password"
                            value={currentPassword}
                            onChange={(e) => setCurrentPassword(e.target.value)}
                            placeholder="Password"
                            className="passwordmodalinput"
                            required
                        />
                        <button 
                            className="applybuttonpasswordmodel" 
                            onClick={() => {
                                if (currentPassword.trim() === "") {
                                    toast.warning("Please enter your password.");
                                } else {
                                    update2FA();
                                    setShowPasswordModalQR(false);
                                }
                            }}
                        >
                            Validate
                        </button>
                        <ToastContainer
                            position="top-center"
                            className="custom-toast-container"
                            toastClassName="custom-toast"
                            bodyClassName="custom-toast-body"
                        />
                    </div>
                </div>
            )} */}
            <ToastContainer
                position="top-center"
                className="custom-toast-container"
                toastClassName="custom-toast"
                bodyClassName="custom-toast-body"
            />
        </div>
    );
}

export default Account;
