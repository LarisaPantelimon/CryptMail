import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faInbox, faShieldAlt, faUser, faQuestionCircle, faBars } from '@fortawesome/free-solid-svg-icons';
import './InfoPage.css';
import logo from '../ImgSrc/logoWhite.png';

const InfoPage = () => {
    const navigate = useNavigate();
    const [isSidebarOpen, setIsSidebarOpen] = useState(true); // Sidebar hidden by default on all screen sizes

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    useEffect(() => {
        //console.log('Sidebar open state:', isSidebarOpen);
    }, [isSidebarOpen]);

    return (
        <div className="info-page-new">
            {/* Toggle Button */}
            <button
                className={`sidebar-new-toggle ${isSidebarOpen ? 'active' : ''}`}
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
            <div className={`sidebar-new ${isSidebarOpen ? 'open' : ''}`}>
                <div className="sidebar-header">
                    <div className="sidebar-logo">
                        <img src={logo} alt="CryptMail Logo" />
                    </div>
                </div>
                <ul className="sidebar-new-menu">
                    <li>
                        <button
                            className="sidebar-new-button"
                            onClick={() => {
                                navigate('/Inbox');
                                setIsSidebarOpen(false);
                            }}
			    style={{ fontSize: '1rem' }}
                            title="Inbox"
                            aria-label="Navigate to Inbox"
                        >
                            <FontAwesomeIcon icon={faInbox} className="sidebar-new-icon" />
                            <span className="sidebar-new-text">Inbox</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="sidebar-new-button"
                            onClick={() => {
                                navigate('/Account');
                                setIsSidebarOpen(false);
                            }}
			    style={{ fontSize: '1rem' }}
                            title="Account Settings"
                            aria-label="Navigate to Account Settings"
                        >
                            <FontAwesomeIcon icon={faUser} className="sidebar-new-icon" />
                            <span className="sidebar-new-text">Account Settings</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="sidebar-new-button"
                            onClick={() => {
                                navigate('/Recovery');
                                setIsSidebarOpen(false);
                            }}
			    style={{ fontSize: '1rem' }}
                            title="Recovery Data"
                            aria-label="Navigate to Recovery Data"
                        >
                            <FontAwesomeIcon icon={faShieldAlt} className="sidebar-new-icon" />
                            <span className="sidebar-new-text">Recovery Data</span>
                        </button>
                    </li>
                    <li>
                        <button
                            className="sidebar-new-button active"
                            onClick={() => {
                                navigate('/info');
                                setIsSidebarOpen(false);
                            }}
                            title="Info Page"
                            aria-label="Navigate to Info Page"
                        >
                            <FontAwesomeIcon icon={faQuestionCircle} className="sidebar-new-icon" />
                            <span className="sidebar-new-text">Info Page</span>
                        </button>
                    </li>
                </ul>
            </div>

            {/* Main Content */}
            <div className={`content-new-wrapper ${isSidebarOpen ? 'shifted' : ''}`}>
                <div className="container-new">
                    <h1 className="page-new-title">CryptMail Security Features</h1>

                    {/* Recovery File Section */}
                    <section className="info-card-new">
                        <h2 className="card-title-new">What is a Recovery File?</h2>
                        <p className="card-text-new">
                            A Recovery File is a secure backup that allows you to regain access to your encrypted data if you forget your password. It acts as a safety net, ensuring your emails and settings remain accessible even in challenging situations.
                        </p>
                        <p className="card-text-new">
                            <strong>Why it's useful:</strong> Without a Recovery File, a forgotten password could permanently lock you out of your account. Generating one provides peace of mind and protects your data from loss.
                        </p>
                        <p className="card-text-new">
                            <strong>How to generate one:</strong> Navigate to the Account and Data Recovery page to create your Recovery File. Follow the prompts to download and store it in a secure location.
                        </p>
                        <button
                            onClick={() => navigate('/Recovery')}
                            className="action-button-new"
                            aria-label="Navigate to Data Recovery page"
                        >
                            <FontAwesomeIcon icon={faShieldAlt} className="button-icon-new" />
                            Go to Data Recovery
                        </button>
                    </section>

                    {/* Key Pair Generation Section */}
                    <section className="info-card-new">
                        <h2 className="card-title-new">Generating a Key Pair</h2>
                        <p className="card-text-new">
                            A key pair consists of a public key and a private key used to encrypt and decrypt your emails. This cryptographic method ensures that only you and the intended recipient can read your messages, keeping your communications secure.
                        </p>
                        <p className="card-text-new">
                            <strong>Why it's important:</strong> Regularly updating your key pair enhances security by minimizing the risk of compromised keys. CryptMail requires a new key pair every 30 days to maintain the highest level of protection.
                        </p>
                        <p className="card-text-new">
                            <strong>Automatic updates:</strong> You'll receive a notification 5 days before your current key pair expires, reminding you to generate a new one. This ensures seamless and secure email functionality.
                        </p>
                        <p className="card-text-new">
                            <strong>How to generate one:</strong> Visit your Profile Settings to create a new key pair. Follow the instructions to generate and securely store your keys.
                        </p>
                        <button
                            onClick={() => navigate('/Account')}
                            className="action-button-new"
                            aria-label="Navigate to Profile Settings page"
                        >
                            <FontAwesomeIcon icon={faUser} className="button-icon-new" />
                            Go to Profile Settings
                        </button>
                    </section>

                    {/* 2FA Section */}
                    <section className="info-card-new">
                        <h2 className="card-title-new">Two-Factor Authentication (2FA)</h2>
                        <p className="card-text-new">
                            Two-Factor Authentication (2FA) adds an extra layer of security by requiring a second form of verification, validating a login request from an authenticator app, in addition to your password.
                        </p>
                        <p className="card-text-new">
                            <strong>Why it's important:</strong> 2FA significantly reduces the risk of unauthorized access, even if your password is compromised. It's a critical step to safeguard your sensitive email data.
                        </p>
                        <p className="card-text-new">
                            <strong>How to enable it:</strong> Enable 2FA from your Profile Settings. You'll need an authenticator app, our custom CryptMail Authenticator, to allow secure acess to your account.
                        </p>
                        <button
                            onClick={() => navigate('/Account')}
                            className="action-button-new"
                            aria-label="Navigate to Profile Settings page"
                        >
                            <FontAwesomeIcon icon={faUser} className="button-icon-new" />
                            Go to Profile Settings
                        </button>
                    </section>
                </div>
            </div>
        </div>
    );
};

export default InfoPage;