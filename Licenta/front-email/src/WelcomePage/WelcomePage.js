import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { ToastContainer, toast } from "react-toastify";
import "./WelcomePage.css";
import logo from '../ImgSrc/image-Photoroom.png';
import secure_email from '../ImgSrc/startup-rocket.gif';
import encr from '../ImgSrc/security.gif';
import auth from '../ImgSrc/login.webp';
import privacy from '../ImgSrc/privacy.jpg';

function WelcomePage() {
    const navigate = useNavigate();

    const handleLogin = () => {
        navigate('/login');
    };

    const handleRegister = () => {
        navigate('/register');
    };

    useEffect(() => {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                }
            });
        }, { threshold: 0.3 });

        const sections = document.querySelectorAll('.section');
        sections.forEach(section => observer.observe(section));

        return () => {
            sections.forEach(section => observer.unobserve(section));
        };
    }, []);

    return (
        <div className="welcome-container">
            <main className="main-content-welcome">
                <div className="first-section-welcome">
                    <div className="hero-content">
                        <h1 className="fade-in">Welcome to CryptMail</h1>
                        <p className="tagline fade-in">Secure. Private. Encrypted Email for Everyone.</p>
                        <div className="cta-buttons fade-in">
                            <button onClick={handleLogin} className="btn login-btn">Login</button>
                            <button onClick={handleRegister} className="btn register-btn">Register</button>
                        </div>
                    </div>
                    <div className="logo-container-welcome">
                        <img src={logo} alt="CryptMail Logo" className="logo animated-logo" />
                    </div>
                </div>

                <div className="section mission-section">
                    <div className="text-content left">
                        <h2>Our Mission</h2>
                        <p>To deliver your emails with absolute confidence—securely encrypted from sender to recipient. We champion privacy, protect your communications, and ensure your messages stay yours, and yours alone.</p>
                    </div>
                    <div className="image-content right">
                        <img src={secure_email} alt="Secure Email" className="section-image" />
                    </div>
                </div>

                <div className="section feature-section">
                    <div className="image-content left">
                        <div className="animated-lock">
                            <img src={encr} alt="Encryption" className="section-image2" />
                        </div>
                    </div>
                    <div className="text-content right">
                        <h3>End-to-End Encryption</h3>
                        <p>Your emails are protected every step of the way—encrypted from the moment they leave your device until they reach your recipient’s inbox. No detours, no snooping. Just pure privacy.</p>
                    </div>
                </div>

                <div className="section feature-section">
                    <div className="text-content left">
                        <h3>Custom Mobile Authenticator</h3>
                        <p>Add an extra layer of defense with our tailor-made mobile authenticator. Designed for seamless security, it's your key to effortless, on-the-go protection.</p>
                    </div>
                    <div className="image-content right">
                        <img src={auth} alt="Mobile Authenticator" className="section-image3" />
                    </div>
                </div>

                <div className="section feature-section">
                    <div className="image-content left">
                        <img src={privacy} alt="Privacy First" className="section-image3" />
                    </div>
                    <div className="text-content right">
                        <h3>Privacy First</h3>
                        <p>Your privacy isn’t a feature—it’s our foundation. No tracking, no ads, no compromises. Just secure, private communication you can trust.</p>
                    </div>
                </div>
            </main>
            <footer className="footer">
                <p>© 2025 CryptMail. All rights reserved.</p>
                <div className="footer-links">
                    <a href="/privacy" className="footer-link">Privacy Policy</a>
                    <a href="/terms" className="footer-link">Terms of Service</a>
                    <a href="/contact" className="footer-link">Contact Us</a>
                </div>
            </footer>
            <ToastContainer />
        </div>
    );
}

export default WelcomePage;