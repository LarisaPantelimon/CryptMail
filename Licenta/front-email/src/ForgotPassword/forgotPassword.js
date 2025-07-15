import React, { useState } from 'react';
import { useLocation } from 'react-router-dom';
import DOMPurify from 'dompurify';
import './forgotPassword.css';
import logo from '../ImgSrc/image-Photoroom.png';
import {
    encryptWithPassword,
    hashPassword,
    generateRsaKeyPairWorker,
} from '../EncDecFunctions/EncDecFunctions';

function ForgotPassword() {
    const location = useLocation();
    const initialEmail = location.state?.email || '';
    const [email, setEmail] = useState(DOMPurify.sanitize(initialEmail));
    const [verificationEmail, setVerificationEmail] = useState('');
    const [code, setCode] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [isEditingInitial, setIsEditingInitial] = useState(false);
    const [isEditingVerification, setIsEditingVerification] = useState(false);
    const [currentStep, setCurrentStep] = useState(1);
    const [isLoading, setIsLoading] = useState(false);
    const [generatedCode, setGeneratedCode] = useState('');

    const isMatch = newPassword === confirmPassword && confirmPassword !== '';
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    const generateCode = () => {
        return Math.floor(100000 + Math.random() * 900000).toString();
    };

    const getRecoveryEmail = async () => {
        setIsLoading(true);
        try {
            const response = await fetch('/api/get-recovery-email', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: DOMPurify.sanitize(email) }),
            });
            const data = await response.json();
            if (response.ok) {
                setVerificationEmail(DOMPurify.sanitize(data.recovery_email || ''));
            } else {
                //console.error('Failed to fetch recovery email');
            }
        } catch (error) {
            //console.error('Error:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleNextStep = async (step) => {
        switch (step) {
            case 1:
                if (email && emailRegex.test(email)) {
                    await getRecoveryEmail();
                    setCurrentStep(2);
                } else {
                    alert('Please enter a valid email');
                }
                break;
            case 2:
                if (verificationEmail && emailRegex.test(verificationEmail)) {
                    setIsLoading(true);
                    const codetoGenerate = generateCode();
                    setGeneratedCode(codetoGenerate);
                    try {
                        //console.log('Sending verification email to:', verificationEmail);
                        const response = await fetch('/api/verify-email', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: DOMPurify.sanitize(verificationEmail), code: codetoGenerate }),
                        });
                        if (!response.ok) {
                            throw new Error('Failed to send verification email.');
                        }
                        alert('Verification email sent! Please check your inbox.');
                        setCurrentStep(3);
                    } catch (error) {
                        //console.error('Error:', error);
                        alert(`An error occurred: ${error.message}`);
                    } finally {
                        setIsLoading(false);
                    }
                } else {
                    alert('Please enter a valid verification email');
                }
                break;
            case 3:
                const sanitizedCode = DOMPurify.sanitize(code);
                if (sanitizedCode && /^\d{6}$/.test(sanitizedCode)) {
                    //console.log('Entered code:', sanitizedCode);
                    //console.log('Generated code:', generatedCode);
                    if (sanitizedCode === generatedCode) {
                        setCurrentStep(4);
                    } else {
                        alert('Codes do not match!');
                    }
                } else {
                    alert('Please enter a valid 6-digit verification code');
                }
                break;
            case 4:
                setIsLoading(true);
                const sanitizedNewPassword = DOMPurify.sanitize(newPassword);
                const sanitizedConfirmPassword = DOMPurify.sanitize(confirmPassword);
                if (
                    sanitizedNewPassword &&
                    sanitizedConfirmPassword &&
                    sanitizedNewPassword === sanitizedConfirmPassword
                ) {
                    //console.log('Generating RSA key pair...');
                    const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairWorker();
                    const encryptedPrivateKey = encryptWithPassword(privateKeyPem, sanitizedNewPassword);
                    const hashedPassword = await hashPassword(sanitizedNewPassword);
                    //console.log('Hashed Password:', hashedPassword);

                    try {
                        const response = await fetch('/api/set-new-password', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                email: DOMPurify.sanitize(email),
                                private_key: encryptedPrivateKey,
                                public_key: publicKeyPem,
                                hashed_password: hashedPassword,
                            }),
                        });

                        if (response.ok) {
                            // Add a delay to ensure UI shows "Loading..."
                            await new Promise(resolve => setTimeout(resolve, 1000)); // 1-second delay
                            window.location.href = '/Login';
                        } else {
                            throw new Error('Failed to reset password');
                        }
                    } catch (error) {
                        //console.error('Error:', error);
                        alert(`An error occurred: ${error.message}`);
                    } finally {
                        setIsLoading(false);
                    }
                } else {
                    alert('Passwords must match and cannot be empty');
                    setIsLoading(false);
                }
                break;
            default:
                break;
        }
    };

    // Card 1: Initial Email
    const renderEmailCard = () => (
        <div className="full-page1">
            <div className="forgot-password-card-page">
                <h2 className="card-title-page">Forgot Password</h2>
                <div className="first-two-elements">
                    <div className="email-input-container">
                        <i className="fas fa-envelope"></i>
                        <input
                            className="input-email-page"
                            type="text"
                            placeholder="Enter recovery email"
                            value={email}
                            onChange={(e) => setEmail(DOMPurify.sanitize(e.target.value))}
                            disabled={!isEditingInitial}
                        />
                    </div>
                    {!isEditingInitial && (
                        <button 
                            className="edit-button-page" 
                            onClick={() => setIsEditingInitial(true)}
                        >
                            Edit
                        </button>
                    )}
                </div>
                <button 
                    className="next-step-button"
                    onClick={() => handleNextStep(1)}
                    disabled={isLoading}
                >
                    {isLoading ? 'Loading...' : 'Next Step'}
                </button>
            </div>
            <div className="logo-forget-password-page">
                <img src={logo} alt="CryptMail Logo" className="logo-forget-password" />
            </div>
        </div>
    );

    // Card 2: Verification Email with fetched data and Edit button
    const renderVerificationEmailCard = () => (
        <div className="full-page1">
            
                {verificationEmail.trim() ? (
                <div className="forgot-password-card-page">
                    <>
                    <h2 className="card-title-page">Verification Email</h2>
                        <div className="first-two-elements">
                            <div className="email-input-container">
                                <i className="fas fa-envelope"></i>
                                <input
                                    className="input-email-page"
                                    type="text"
                                    placeholder={isLoading ? "Fetching..." : "Enter verification email"}
                                    value={isLoading ? '' : verificationEmail}
                                    onChange={(e) => setVerificationEmail(DOMPurify.sanitize(e.target.value))}
                                    disabled={isLoading}
                                />
                            </div>
                        </div>
                        <div className="button-group">
                            <button 
                                className="next-step-button back-button"
                                onClick={() => setCurrentStep(1)}
                                disabled={isLoading}
                            >
                                Back
                            </button>
                            <button 
                                className="next-step-button"
                                onClick={() => handleNextStep(2)}
                                disabled={isLoading}
                            >
                                {isLoading ? 'Sending...' : 'Next Step'}
                            </button>
                        </div>
                    </>
                    </div>
                ) : (
                    <>
                    <div className='forgot-password-card-page'>
                        <h2 className="card-title-page">Verication Email Not Found</h2>
                        <p className="error-message" style={{ color: 'red', marginBottom: '20px' }}>
                            You cannot proceed. We did not find a recovery email associated with this account.
                        </p>
                        <div className="button-group">
                            <button 
                                className="next-step-button back-button"
                                onClick={() => setCurrentStep(1)}
                                disabled={isLoading}
                            >
                                Back
                            </button>
                        </div>
                    </div>
                    </>
                )}
            
            <div className="logo-forget-password-page">
                <img src={logo} alt="CryptMail Logo" className="logo-forget-password" />
            </div>
        </div>
    );

    // Card 3: Verification Code
    const renderCodeCard = () => (
        <div className="full-page1">
            <div className="forgot-password-card-page">
                <h2 className="card-title-page">Enter Verification Code</h2>
                <div className="first-two-elements">
                    <div className="email-input-container">
                        <i className="fas fa-key"></i>
                        <input
                            className="input-email-page"
                            type="text"
                            placeholder="Enter code"
                            value={code}
                            onChange={(e) => setCode(DOMPurify.sanitize(e.target.value))}
                        />
                    </div>
                </div>
                <div className="button-group">
                    <button 
                        className="next-step-button back-button"
                        onClick={() => setCurrentStep(2)}
                    >
                        Back
                    </button>
                    <button 
                        className="next-step-button"
                        onClick={() => handleNextStep(3)}
                    >
                        Next Step
                    </button>
                </div>
            </div>
            <div className="logo-forget-password-page">
                <img src={logo} alt="CryptMail Logo" className="logo-forget-password" />
            </div>
        </div>
    );

    // Card 4: Reset Password
    const renderPasswordResetCard = () => (
        <div className="full-page1">
            <div className="forgot-password-card-page2">
                <h2 className="card-title-page">Reset Password</h2>
                <div className="first-two-elements">
                    <div className="email-input-container">
                        <i className="fas fa-lock"></i>
                        <input
                            className="input-email-page"
                            type="password"
                            placeholder="New password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(DOMPurify.sanitize(e.target.value))}
                        />
                    </div>
                </div>
                <div className="first-two-elements">
                    <div className="email-input-container">
                        <i className="fas fa-lock"></i>
                        <input
                            className={confirmPassword ? (isMatch ? 'match-password' : 'no-match-password') : 'input-email-page'}
                            type="password"
                            placeholder="Confirm password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(DOMPurify.sanitize(e.target.value))}
                        />
                    </div>
                </div>
                <div className="button-group">
                    <button 
                        className="next-step-button back-button"
                        onClick={() => setCurrentStep(3)}
                    >
                        Back
                    </button>
                    <button 
                        className="next-step-button"
                        onClick={() => handleNextStep(4)}
                        disabled={isLoading}
                    >
                        {isLoading ? 'Loading...' : 'Reset Password'}
                    </button>
                </div>
            </div>
            <div className="logo-forget-password-page">
                <img src={logo} alt="CryptMail Logo" className="logo-forget-password" />
            </div>
        </div>
    );

    return (
        <div className="forgot-password-container-page">
            {currentStep === 1 && renderEmailCard()}
            {currentStep === 2 && renderVerificationEmailCard()}
            {currentStep === 3 && renderCodeCard()}
            {currentStep === 4 && renderPasswordResetCard()}
        </div>
    );
}

export default ForgotPassword;