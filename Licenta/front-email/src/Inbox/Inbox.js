import React, { useState, useEffect, useRef, useContext, useCallback} from 'react';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldAlt, faCog, faUser, faInbox, faStar, faPlus, faPaperPlane, faTrash, faEnvelope, faVault, faCircleExclamation, faRotate, faEnvelopeOpen, faQuestionCircle, faAddressBook, faRightFromBracket, faArchive } from '@fortawesome/free-solid-svg-icons';
import './Inbox.css';
import ComposeEmail from '../Compose_Email/compose.js';
import parse from "emailjs-mime-parser";
import CryptoJS from 'crypto-js';
import { useNavigate } from 'react-router-dom';
import forge from 'node-forge';
import logo from '../ImgSrc/logoWhite.png';
import CustomFolders from './CustomFolders';
import { AuthContext } from '../Login/AuthContext';
import {
    parseFinalMessage,
    decryptSymmetricKeyWithRsa,
    decryptMessage,
    decompressMessage,
    firstVerification,
    verifyMessage
} from './decryption.js';

import {
    handleAddContact,
    handleDeleteContact,
    getContacts,
    fetchCustomFolders,
} from './helpInbox.js';

function Inbox() {
    const [hoveredEmail, setHoveredEmail] = useState(null);
    const [error, setError] = useState('');
    const [emails, setEmails] = useState([]);
    const [filteredEmails, setFilteredEmails] = useState([]);
    const [email, setEmail] = useState('');
    const [selectedEmail, setSelectedEmail] = useState(null);
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [selectedCategory, setSelectedCategory] = useState('Inbox');
    const [isComposeOpen, setIsComposeOpen] = useState(false);
    const [selectedEmailDetails, setSelectedEmailDetails] = useState(null);
    const [checkedEmails, setCheckedEmails] = useState([]);
    const [contacts, setContacts] = useState([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [isContactsOpen, setIsContactsOpen] = useState(false);
    const [showEmailModal, setShowEmailModal] = useState(false);
    const [newEmail, setNewEmail] = useState('');
    const [selectedRecipient, setSelectedRecipient] = useState('');
    const [customFolders, setCustomFolders] = useState([]);
    const [previewAttachment, setPreviewAttachment] = useState(null);
    const toastIds = useRef(new Set());
    const hasFetchedKey = useRef(false);
    const modalRef = useRef(null);
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);

    const supportedPreviewTypes = {
        pdf: { type: 'pdf', mime: 'application/pdf' },
        jpg: { type: 'image', mime: 'image/jpeg' },
        jpeg: { type: 'image', mime: 'image/jpeg' },
        png: { type: 'image', mime: 'image/png' },
        gif: { type: 'image', mime: 'image/gif' },
        webp: { type: 'image', mime: 'image/webp' },
        svg: { type: 'image', mime: 'image/svg+xml' },
        txt: { type: 'text', mime: 'text/plain' },
        csv: { type: 'text', mime: 'text/csv' },
        html: { type: 'text', mime: 'text/html' },
        xml: { type: 'text', mime: 'text/xml' },
        json: { type: 'text', mime: 'application/json' },
    };

    const navigate = useNavigate();

    const toggleCompose = () => {
        setIsComposeOpen(!isComposeOpen);
    };

    useEffect(() => {
        const fetchUserEmail = async () => {
            try {
                //console.log("Fetching user email...");
                const response = await fetchWithAuth('/api/get-email', {
                    method: 'GET',
                    credentials: 'include'
                });

                const data = await response.json();
                if (response.ok) {
                    setEmail(data.email);
                    setTimeout(() => {
                        fetchEmails(data.email);
                        getContacts().then(setContacts);
                        fetchMyLatestKey(data.email);
                        fetchCustomFolders().then(setCustomFolders);
                    }, 0);
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

    useEffect(() => {
        if (!email) return;

        const intervalId = setInterval(() => {
            //console.log('Polling for new emails...');
            fetchEmails(email);
        }, 10000);

        return () => clearInterval(intervalId);
    }, [email]);

    useEffect(() => {
        if (email && !hasFetchedKey.current) {
            hasFetchedKey.current = true;
            fetchMyLatestKey(email);
        }
    }, [email]);

    const showToast = (type, message, id) => {
        if (!toastIds.current.has(id)) {
            toastIds.current.add(id);
            //console.log(`Showing ${type} toast with ID: ${id}`);
            switch (type) {
                case 'success':
                    toast.success(message, { toastId: id });
                    break;
                case 'warning':
                    toast.warning(message, { toastId: id });
                    break;
                case 'error':
                    toast.error(message, { toastId: id });
                    break;
                default:
                    break;
            }
        } else {
            //console.log(`Toast with ID ${id} already shown, skipping.`);
        }
    };

    useEffect(() => {
        filterEmails();
    }, [emails, selectedCategory, searchQuery]);

    const handleKeyDown = useCallback((event) => {
        if (event.key === 'Escape' && previewAttachment) {
            setPreviewAttachment(null);
        }
    }, [previewAttachment]);

    useEffect(() => {
        if (previewAttachment && modalRef.current) {
            modalRef.current.focus();
            document.addEventListener('keydown', handleKeyDown);
        }
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [previewAttachment, handleKeyDown]);

    const handleChildError = (message, details) => {
        const errorMessage = `${message} ${details || ''}`.trim();
        showToast('error', errorMessage, 'compose-email-error');
        toastIds.current.delete('compose-email-error');
    };

    const fetchMyLatestKey = async (receiverEmail) => {
        //console.log('fetchMyLatestKey called with:', receiverEmail);
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-last-key', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ receiver_email: receiverEmail }),
            });

            const data = await response.json();
            if (response.ok) {
                if (data.PublicKey === null) {
                    if (receiverEmail === email) {
                        showToast('error', "Your Public Key is expired! Please generate a new one from the Profile Settings!", 'key-expired-user');
                    } else {
                        showToast('error', "The receiver's Public Key is expired! Try again later.", 'key-expired-receiver');
                    }
                    return;
                }

                const expirationDate = new Date(data.ExpirationDate);
                const today = new Date();
                const timeDiff = expirationDate - today;
                const daysLeft = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));

                if (daysLeft <= 5) {
                    showToast('warning', `Your key expires in ${daysLeft} days! Consider renewing it.`, 'key-expires-soon');
                } else {
                    showToast('success', "Your key is still good!", 'key-still-good');
                }
                return { public_key: data.PublicKey, key_id: data.KeyId };
            } else {
                throw new Error(data.error || "Failed to fetch receiver's public key");
            }
        } catch (error) {
            //console.error("Error fetching receiver's public key:", error);
            throw error;
        }
    };

    const fetchMyPrvKey = async (email, keyId) => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-myprivatekey', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ email: email, key_id: keyId }),
            });

            const data = await response.json();
            if (response.ok) {
                return data.PrivateKey;
            } else {
                throw new Error(data.error || "Failed to fetch private key");
            }
        } catch (error) {
            //console.error("Error fetching private key:", error);
            throw error;
        }
    };

    const fetchReceiverKey = async (email, KeyId) => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            //console.log("================Fetching receiver key for:", email);
            const response = await fetchWithAuth('/api/get-receiver-key', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ receiver_email: email, key_id: KeyId }),
            });

            const data = await response.json();
            if (response.ok) {
                return { public_key: data.PublicKey };
            } else {
                throw new Error(data.error || "Failed to fetch public key");
            }
        } catch (error) {
            //console.error("Error fetching public key:", error);
            throw error;
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
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
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

    const decryptWithPassword = (encryptedPrivateKey, password) => {
        try {
            //console.log("Attempting to decrypt with password:", password);
            if (typeof encryptedPrivateKey !== 'string' || encryptedPrivateKey.length === 0) {
                toast.error("Encrypted private key is not in a valid format.");
                //throw new Error("Encrypted private key is not in a valid format.");
            }

            const privateKey = forge.pki.decryptRsaPrivateKey(encryptedPrivateKey, password);
            if (!privateKey) {
                toast.error("Decryption failed. Incorrect password or corrupted data.");
                //throw new Error("Decryption failed. Incorrect password or corrupted data.");
            }

            const decryptedPrivateKeyPem = forge.pki.privateKeyToPem(privateKey);
            return decryptedPrivateKeyPem;
        } catch (error) {
            toast.error("Decryption error:", error.message);
            //throw new Error("Failed to decrypt private key. Please check your password and try again.");
        }
    };

    const fetchEmailDetails = async (emailID, sent, receive, emailMes) => {
        try {
            let folder = sent === 1 ? 'Sent/' : receive === 1 ? 'Received/' : null;
            if (!folder) throw new Error('Invalid folder: must specify sent or receive');

            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];

            const response = await fetchWithAuth('/api/inbox/fetch-email-content', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken
                },
                body: JSON.stringify({ email_id: emailID, folder: folder })
            });

            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }

            const data = await response.json();
            if (!data.MimeMessage) {
                throw new Error('No MimeMessage in response');
            }

            //console.log('MimeMessage Length:', data.MimeMessage.length);
            //console.log('MimeMessage Preview:', data.MimeMessage.slice(0, 100) + '...');
            //console.log('MimeMessage Valid Base64:', /^[A-Za-z0-9+/=]+$/.test(data.MimeMessage));
            const decodedEmail = parseFinalMessage(data.MimeMessage);

            const processEmail = async () => {
                try {
                    const KeyIdFromMessage = decodedEmail.key_id;
                    const encryptedPrivateKey = await fetchMyPrvKey(emailMes.Receiver, KeyIdFromMessage);
                    const sessionKey = await fetchSessionKey();
                    const encryptedPassword = sessionStorage.getItem('x7k9p2m');

                    if (!encryptedPrivateKey) {
                        throw new Error('Encrypted private key not found. Please log in again.');
                    }

                    let decryptedPassword = CryptoJS.AES.decrypt(encryptedPassword, sessionKey).toString(CryptoJS.enc.Utf8);
                    if (!decryptedPassword) {
                        toast.error('Failed to decrypt private key. Please check your session key.');
                        return;
                    }

                    let decryptedPrivateKey = decryptWithPassword(encryptedPrivateKey, decryptedPassword);
                    if (!decryptedPrivateKey.includes('-----BEGIN')) {
                        decryptedPrivateKey = `-----BEGIN RSA PRIVATE KEY-----\n${decryptedPrivateKey}\n-----END RSA PRIVATE KEY-----`;
                    }

                    const decryptedSymmetricKey = await decryptSymmetricKeyWithRsa(decodedEmail, decryptedPrivateKey);
                    //console.log('Decrypted Symmetric Key:', decryptedSymmetricKey);

                    const decryptedMessage = await decryptMessage(decodedEmail.ciphertext, decryptedSymmetricKey);
                    //console.log('Decrypted Message Length:', decryptedMessage.length / 1024 / 1024, 'MB');

                    const decompressedMessage = await decompressMessage(decryptedMessage);
                    //console.log('Decompressed Message:', decompressedMessage);

                    const firstVerificationResult = await firstVerification(decompressedMessage);
                    //console.log('First Verification Result:', firstVerificationResult);

                    if (firstVerificationResult) {
                        const { public_key: senderPublicKey } = await fetchReceiverKey(
                            emailMes.Sender,
                            decompressedMessage.signature_part.public_key_id
                        );
                        if (!senderPublicKey) {
                            throw new Error(`Failed to fetch public key for sender: ${emailMes.Sender}`);
                        }
                        //console.log('Sender Public Key:', senderPublicKey.slice(0, 50) + '...');
                        const secondVerificationResult = await verifyMessage(decompressedMessage, senderPublicKey);
                        //console.log('Second Verification Result:', secondVerificationResult);

                        if (secondVerificationResult) {
                            if (!(decompressedMessage.message_part instanceof Uint8Array)) {
                                //console.error('Invalid message_part:', decompressedMessage.message_part);
                                throw new Error('message_part is not a Uint8Array');
                            }
                            const mimeString = new TextDecoder().decode(decompressedMessage.message_part);
                            if (typeof mimeString !== 'string' || mimeString.length === 0) {
                                //console.error('Failed to decode message_part:', mimeString);
                                throw new Error('Failed to decode message_part to a string');
                            }
                            //console.log('MIME String Preview:', mimeString.slice(0, 100) + '...');
                            //console.log('MIME String Length:', mimeString.length);
                            const parsedEmail = parseMimeMessage(mimeString);
                            return {
                                ...emailMes,
                                Body: parsedEmail.body,
                                Attachments: parsedEmail.attachments
                            };
                        } else {
                            throw new Error('Second verification failed');
                        }
                    } else {
                        throw new Error('First verification failed');
                    }
                } catch (error) {
                    //console.error('Error processing email:', error);
                    throw error;
                }
            };

            let emailDetails;
            if (receive === 1) {
                //console.log('Processing received email');
                emailDetails = await processEmail();
            } else if (sent === 1) {
                //console.log('Processing sent email');
                emailDetails = await processEmail();
            } else {
                throw new Error('Invalid email type: must be sent or received');
            }

            setSelectedEmailDetails(emailDetails);
        } catch (error) {
            //console.error('Failed to fetch email details:', error);
            showToast('error', 'Failed to load email details.', 'email-details-error');
        }
    };

    const fetchEmails = async (userEmail) => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/inbox/fetch-emails', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ email: userEmail })
            });

            const data = await response.json();
            if (response.ok) {
                //console.log("Emails received successfully:", data.emails);
                setEmails(data.emails);
            } else {
                //console.error("Error fetching emails:", data.error);
                setError(data.error || "Failed to load emails. Please try again.");
            }
        } catch (error) {
            //console.error("Error:", error);
            setError("Failed to load emails. Please try again.");
        }
    };

    const markEmailAsRead = async (emailId, sender, receiver) => {
        const csrfToken = document.cookie
            .split('; ')
            .find((row) => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/inbox/mark-email-read', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ emailId, email, sender, receiver }),
            });

            const data = await response.json();
            if (response.ok) {
                //console.log(`Email ${emailId} marked as read.`);
                setEmails((prevEmails) =>
                    prevEmails.map((email) =>
                        email.EmailID === emailId ? { ...email, IsRead: 1 } : email
                    )
                );
                filterEmails();
            } else {
                //console.error('Failed to mark email as read:', data.error);
                setError(data.error || 'Failed to mark email as read.');
            }
        } catch (error) {
            //console.error('Error marking email as read:', error);
            setError('Failed to mark email as read. Please try again.');
        }
    };

    const parseMimeMessage = (mimeMessage) => {
        try {
            //console.log('parseMimeMessage Input Type:', typeof mimeMessage);
            //console.log('parseMimeMessage Input Preview:', typeof mimeMessage === 'string' ? mimeMessage.slice(0, 100) + '...' : mimeMessage);
            if (typeof mimeMessage !== 'string') {
                throw new Error('Invalid MIME message: must be a string');
            }
            if (!parse || typeof parse !== 'function') {
                throw new Error('Parse function is not available. Ensure mailparser is imported.');
            }

            const parsed = parse(mimeMessage);
            if (!parsed || typeof parsed !== 'object') {
                throw new Error('Failed to parse MIME message: invalid output');
            }

            let body = "";
            const attachments = [];

            const processPart = (part) => {
                if (part.childNodes && part.childNodes.length > 0) {
                    part.childNodes.forEach(processPart);
                } else {
                    if (part.contentType?.value === "text/plain") {
                        body = new TextDecoder().decode(part.content);
                    } else if (part.contentType?.value === "text/html" && !body) {
                        body = new TextDecoder().decode(part.content);
                    } else if (part.disposition === "attachment" || part.contentType?.value === "application/octet-stream") {
                        const filename = part.filename ||
                            part.headers?.['content-disposition']?.[0]?.params?.filename ||
                            "Unnamed attachment";
                        const content = part.content;
                        const content_type = part.contentType?.value || "application/octet-stream";
                        attachments.push({
                            filename,
                            content,
                            content_type
                        });
                    }
                }
            };

            processPart(parsed);
            //console.log('Parsed Body Length:', body.length);
            // console.log('Parsed Attachments:', attachments.map(a => ({
            //     filename: a.filename,
            //     content_type: a.content_type,
            //     content_length: a.content instanceof Uint8Array ? a.content.length : 'Not a Uint8Array'
            // })));
            return { body, attachments };
        } catch (error) {
            //console.error("Error parsing MIME message:", error);
            return { subject: "Error", body: "Failed to parse email", attachments: [] };
        }
    };

    const toggleEmailDetails = (index, emailID, sent, received, emailMes) => {
        if (selectedEmail === index) {
            setSelectedEmail(null);
            setSelectedEmailDetails(null);
            setPreviewAttachment(null);
        } else {
            setSelectedEmail(index);
            if (emailMes.IsRead === false && received === 1) {
                markEmailAsRead(emailID, emailMes.Sender, emailMes.Receiver);
            }
            fetchEmailDetails(emailID, sent, received, emailMes);
        }
    };

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    const selectCategory = (category) => {
        setSelectedCategory(category);
    };

    const handleSelectAll = (e) => {
        if (e.target.checked) {
            setCheckedEmails(filteredEmails.map(mail => mail.EmailID));
        } else {
            setCheckedEmails([]);
        }
    };

    const handleBulkAction = async (action) => {
        if (checkedEmails.length === 0) {
            toast.warn('No emails selected');
            return;
        }
        try {
            const selectedEmails = filteredEmails.filter(mail => checkedEmails.includes(mail.EmailID));
            const promises = selectedEmails.map(async (mail) => {
                if (action === 'Read') {
                    if (!mail.IsRead) {
                        await markEmailAsRead(mail.EmailID, mail.Sender, mail.Receiver);
                    }
                } else if (action === 'Unread') {
                    if (mail.IsRead) {
                        await markEmailAsUnread(mail.EmailID, mail.Sender, mail.Receiver);
                    }
                } else {
                    if (customFolders.includes(action)) {
                        await handleMoveToFolder(mail.EmailID, action, mail.Sender, mail.Receiver);
                    } else {
                        await handleAction(mail.EmailID, action, mail.Folder, mail.Sender, mail.Receiver);
                    }
                }
            });
            await Promise.all(promises);
            setCheckedEmails([]);
            toast.success(`Successfully applied ${action} to ${checkedEmails.length} email${checkedEmails.length > 1 ? 's' : ''}`);
        } catch (error) {
            //console.error(`Error performing bulk ${action}:`, error);
            toast.error(`Failed to apply ${action} to selected emails`);
        }
    };

    const handleRefresh = async () => {
        try {
            await fetchEmails(email);
        } catch (error) {
            //console.error("Error refreshing emails:", error);
            setError("Failed to refresh emails. Please try again.");
        }
    };

    const markEmailAsUnread = async (emailId, sender, receiver) => {
        const csrfToken = document.cookie
            .split('; ')
            .find((row) => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/inbox/mark-email-unread', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({ emailId, email, sender, receiver }),
            });

            const data = await response.json();
            if (response.ok) {
                //console.log(`Email ${emailId} marked as unread.`);
                setEmails((prevEmails) =>
                    prevEmails.map((email) =>
                        email.EmailID === emailId ? { ...email, IsRead: 0 } : email
                    )
                );
                filterEmails();
            } else {
                //console.error('Failed to mark email as unread:', data.error);
                setError(data.error || 'Failed to mark email as unread.');
            }
        } catch (error) {
            //console.error('Error marking email as unread:', error);
            setError('Failed to mark email as unread. Please try again.');
        }
    };

    const filterEmails = () => {
        let filtered = [];
        const seenEmails = new Set();

        if (selectedCategory === 'All') {
            filtered = emails.filter(mail => mail.Folder !== 'Trash' && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID));
        } else if (selectedCategory === 'Inbox') {
            filtered = emails.filter(mail =>
                mail.Folder === 'Inbox' && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        } else if (selectedCategory === 'Favorite') {
            filtered = emails.filter(mail =>
                mail.Folder === 'Favorite' && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        } else if (selectedCategory === 'Sent') {
            filtered = emails.filter(mail =>
                (mail.Folder === 'Sent') && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        } else if (selectedCategory === 'Trash') {
            filtered = emails.filter(mail =>
                mail.Folder === 'Trash' && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        } else if (selectedCategory === 'Spam') {
            filtered = emails.filter(mail =>
                mail.Folder === 'Spam' && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        } else {
            filtered = emails.filter(mail =>
                mail.Folder === selectedCategory && !seenEmails.has(mail.EmailID) && seenEmails.add(mail.EmailID)
            );
        }

        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            filtered = filtered.filter(
                (mail) =>
                    mail.Subject.toLowerCase().includes(query) ||
                    mail.Sender.toLowerCase().includes(query)
            );
        }

        //console.log('Filtered Emails:', filtered);
        setFilteredEmails(filtered);
    };

    const handleAction = async (emailId, action, folder, sender, receiver) => {
        try {
            //console.log(emailId, action, folder);
            if (action === 'Trash' && folder === 'Trash') {
                const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];
                const response = await fetchWithAuth('/api/inbox/delete-email', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                    body: JSON.stringify({ emailId, email, sender, receiver }),
                });

                const data = await response.json();
                if (response.ok) {
                    //console.log(`Email ${emailId} deleted permanently.`);
                    setEmails((prevEmails) => prevEmails.filter((email) => email.EmailID !== emailId));
                } else {
                    //console.error('Failed to delete email:', data.error);
                    setError(data.error || 'Failed to delete email.');
                }
            } else {
                const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];
                const response = await fetch('/api/inbox/update-email', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                    body: JSON.stringify({ emailId, action, email, sender, receiver }),
                });

                const data = await response.json();
                if (response.ok) {
                    //console.log(`Email ${emailId} moved to ${action}.`);
                    setEmails((prevEmails) =>
                        prevEmails.map((email) =>
                            email.EmailID === emailId ? { ...email, Folder: action } : email
                        )
                    );
                    filterEmails();
                } else {
                    //console.error('Failed to update email:', data.error);
                    setError(data.error || 'Failed to update email.');
                }
            }
        } catch (error) {
            //console.error('Error updating email:', error);
            setError('Failed to update email. Please try again.');
        }
    };

    const handleAccountPage = () => {
        navigate('/Account');
    };

    const handleRecoveryPage = () => {
        navigate('/Recovery');
    };

    const handleHover = (index) => {
        setHoveredEmail(index);
    };

    const handleLeave = () => {
        setHoveredEmail(null);
    };

    const downloadAttachment = (attachment) => {
        try {
            let byteArray;
            if (attachment.content instanceof Uint8Array) {
                byteArray = attachment.content;
            } else {
                throw new Error('Attachment content must be a Uint8Array');
            }

            // console.log('Downloading Attachment:', {
            //     filename: attachment.filename,
            //     content_type: attachment.content_type,
            //     content_length: byteArray.length
            // });

            const blob = new Blob([byteArray], { type: attachment.content_type });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = attachment.filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
        } catch (error) {
            //console.error('Error downloading attachment:', error);
            showToast('error', 'Failed to download attachment: ' + error.message, 'download-attachment-error');
        }
    };

    const handleMoveToFolder = async (emailId, folderName, sender, receiver) => {
        try {
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];
            const response = await fetch('/api/inbox/update-email', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({ emailId, action: folderName, email, sender, receiver }),
            });

            const data = await response.json();
            if (response.ok) {
                //console.log(`Email ${emailId} moved to ${folderName}.`);
                setEmails((prevEmails) =>
                    prevEmails.map((email) =>
                        email.EmailID === emailId ? { ...email, Folder: folderName } : email
                    )
                );
                filterEmails();
                toast.success(`Email moved to ${folderName}`);
            } else {
                //console.error('Failed to move email:', data.error);
                toast.error(data.error || 'Failed to move email.');
            }
        } catch (error) {
            //console.error('Error moving email:', error);
            toast.error('Failed to move email. Please try again.');
        }
    };

    const handleCheckboxChange = (e, emailID) => {
        if (e.target.checked) {
            setCheckedEmails(prev => [...prev, emailID]);
        } else {
            setCheckedEmails(prev => prev.filter(id => id !== emailID));
        }
    };

    const handleSearchChange = (e) => {
        setSearchQuery(e.target.value);
    };

    const Logout = async () => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/logout', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
            });

            if (response.ok) {
                //console.log("Logout successful");
                navigate('/login');
            } else {
                //console.error("Logout failed:", response.statusText);
            }
        } catch (error) {
            //console.error("Error during logout:", error);
        }
    };

    const isPreviewable = (attachment) => {
        return !!getPreviewType(attachment);
    };

    const getPreviewType = (attachment) => {
        const mimeEntry = Object.values(supportedPreviewTypes).find(
            (entry) => entry.mime === attachment.content_type.toLowerCase()
        );
        if (mimeEntry) {
            return mimeEntry.type;
        }

        const extension = attachment.filename.split('.').pop().toLowerCase();
        const fileEntry = supportedPreviewTypes[extension];
        return fileEntry ? fileEntry.type : null;
    };

    const uint8ArrayToBase64 = (uint8Array) => {
        try {
            const binary = Array.from(uint8Array).map(byte => String.fromCharCode(byte)).join('');
            return btoa(binary);
        } catch (error) {
            //console.error('Error converting Uint8Array to base64:', error);
            showToast('error', 'Failed to process attachment preview.', 'base64-conversion-error');
            return '';
        }
    };

    const getDataUrl = (attachment) => {
        const base64 = uint8ArrayToBase64(attachment.content);
        if (!base64) return '';
        const mime = supportedPreviewTypes[attachment.filename.split('.').pop().toLowerCase()]?.mime || attachment.content_type;
        return `data:${mime};base64,${base64}`;
    };

    const getTextContent = (attachment) => {
        try {
            return new TextDecoder().decode(attachment.content);
        } catch (error) {
            //console.error('Error decoding text content:', error);
            showToast('error', 'Failed to decode text content.', 'text-decode-error');
            return 'Unable to decode text content.';
        }
    };

    const getPreviewUrl = (attachment) => {
        if (getPreviewType(attachment) === 'pdf') {
            try {
                const blob = new Blob([attachment.content], { type: 'application/pdf' });
                return URL.createObjectURL(blob);
            } catch (error) {
                //console.error('Error creating Blob URL for PDF:', error);
                showToast('error', 'Failed to generate PDF preview.', 'pdf-blob-error');
                return '';
            }
        }
        return getDataUrl(attachment);
    };

    const AttachmentPreview = ({ attachment }) => {
        const previewType = getPreviewType(attachment);
        const [isLoading, setIsLoading] = useState(true);
        const [previewUrl, setPreviewUrl] = useState('');

        useEffect(() => {
            const url = getPreviewUrl(attachment);
            setPreviewUrl(url);
            setIsLoading(false);
            return () => {
                if (previewType === 'pdf' && url) {
                    URL.revokeObjectURL(url);
                }
            };
        }, [attachment, previewType]);

        if (!previewType) {
            return <p className="text-red-500">Preview not available for this file type.</p>;
        }

        return (
            <div
                className="preview-modal flex items-center justify-center"
                role="dialog"
                aria-modal="true"
                aria-label={`Preview of ${attachment.filename}`}
                ref={modalRef}
                tabIndex={-1}
            >
                <div className="preview-backdrop" onClick={() => setPreviewAttachment(null)}></div>
                <div className="preview-content">
                    <div className="preview-header">
                        <h3 className="preview-title">Preview: {attachment.filename}</h3>
                        <button
                            className="preview-close-button"
                            onClick={() => setPreviewAttachment(null)}
                            aria-label="Close preview"
                        >
                            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>
                    <div className="preview-body">
                        {isLoading ? (
                            <div className="preview-loading">
                                <svg className="animate-spin h-8 w-8 text-blue-500 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                <p className="text-center mt-2">Loading preview...</p>
                            </div>
                        ) : (
                            <>
                                {previewType === 'pdf' && previewUrl && (
                                    <iframe
                                        src={previewUrl}
                                        title={attachment.filename}
                                        className="preview-iframe"
                                        onError={() => {
                                            //console.error('Error loading PDF in iframe');
                                            showToast('error', 'Failed to load PDF preview.', 'pdf-load-error');
                                        }}
                                    />
                                )}
                                {previewType === 'image' && (
                                    <img
                                        src={previewUrl}
                                        alt={attachment.filename}
                                        className="preview-image"
                                        onError={() => {
                                            //console.error('Error loading image');
                                            showToast('error', 'Failed to load image preview.', 'image-load-error');
                                        }}
                                    />
                                )}
                                {previewType === 'text' && (
                                    <pre className="preview-text">
                                        {getTextContent(attachment)}
                                    </pre>
                                )}
                            </>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    return (
        <div className="InboxPage">
            <div className={`sidebar ${isSidebarOpen ? 'open' : ''}`}>
                <div className="logo">
                    {isSidebarOpen && (
                        <img src={logo} alt="CryptMail Logo" />
                    )}
                </div>
                <button className="sidebar-toggle" onClick={toggleSidebar}>
                    {isSidebarOpen ? '←' : '☰'}
                </button>
                <button className="write-button" onClick={() => { setSelectedRecipient(''); toggleCompose(); }}>
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"></path>
                    </svg>
                    {isSidebarOpen && <span>Write</span>}
                </button>
                <ul className="listamea">
                    {['Inbox', 'Favorite', 'Sent', 'Trash', 'All', 'Archive'].map((category) => (
                        <li
                            key={category}
                            className={selectedCategory === category ? 'active' : ''}
                            onClick={() => selectCategory(category)}
                        >
                            <FontAwesomeIcon
                                className="icon"
                                icon={
                                    category === 'Inbox' ? faInbox :
                                    category === 'Favorite' ? faStar :
                                    category === 'Sent' ? faPaperPlane :
                                    category === 'Trash' ? faTrash :
                                    category === 'All' ? faEnvelope :
                                    category === 'Archive' ? faArchive :
                                    faCircleExclamation
                                }
                            />
                            <span className={`category-text ${isSidebarOpen ? 'show' : 'hide'}`}>
                                {category}
                            </span>
                        </li>
                    ))}
                </ul>
                {isSidebarOpen && (
                    <CustomFolders
                        selectCategory={selectCategory}
                        selectedCategory={selectedCategory}
                        customFolders={customFolders}
                        setCustomFolders={setCustomFolders}
                    />
                )}
            </div>

            {error && <p className="error">{error}</p>}

            <div className="MainContainer">
                <div className="ViewContainer">
                    <header className="header">
                        <div className="search-bar">
                            <input
                                type="text"
                                placeholder="Search emails..."
                                value={searchQuery}
                                onChange={handleSearchChange}
                            />
                        </div>
                        <div className="actions">
                            <input
                                type="checkbox"
                                className="email-checkbox2"
                                checked={checkedEmails.length === filteredEmails.length && filteredEmails.length > 0}
                                onChange={handleSelectAll}
                                onClick={(e) => e.stopPropagation()}
                            />
                            <button title="Refresh" className="special-button" onClick={(e) => { e.stopPropagation(); handleRefresh(); }}>
                                <FontAwesomeIcon className="icon2" icon={faRotate} />
                            </button>
                            <button title="Trash" className="special-button" onClick={(e) => { e.stopPropagation(); handleBulkAction('Trash'); }}>
                                <FontAwesomeIcon className="icon2" icon={faTrash} />
                            </button>
                            <button title="Archive" className="special-button" onClick={(e) => { e.stopPropagation(); handleBulkAction('Archive'); }}>
                                <FontAwesomeIcon className="icon2" icon={faArchive} />
                            </button>
                            <button title="Mark as Read" className="special-button" onClick={(e) => { e.stopPropagation(); handleBulkAction('Read'); }}>
                                <FontAwesomeIcon className="icon2" icon={faEnvelopeOpen} />
                            </button>
                            <button title="Mark as Unread" className="special-button" onClick={(e) => { e.stopPropagation(); handleBulkAction('Unread'); }}>
                                <FontAwesomeIcon className="icon2" icon={faEnvelope} />
                            </button>
                            <select
                                className="special-button"
                                title="Move to Folder"
                                aria-label="Move selected emails to folder"
                                onChange={(e) => {
                                    if (e.target.value) {
                                        handleBulkAction(e.target.value);
                                        e.target.value = '';
                                    }
                                }}
                            >
                                <option value="">Move to...</option>
                                {customFolders.map((folder) => (
                                    <option key={folder} value={folder}>{folder}</option>
                                ))}
                            </select>
                        </div>
                    </header>

                    {selectedEmail === null ? (
                        <div className="email-list">
                            <div className="email-list-header">
                                <span className="checkbox-placeholder"></span>
                                <span className="email-subject">Subject</span>
                                <span className="email-sender">Sender</span>
                                <span className="email-date">Date & Time</span>
                            </div>
                            {filteredEmails.length > 0 ? (
                                filteredEmails.slice().reverse().map((mail, index) => (
                                    <div
                                        key={index}
                                        className={`email-item ${mail.IsRead === false ? 'unread' : ''}`}
                                        onMouseEnter={() => handleHover(index)}
                                        onMouseLeave={handleLeave}
                                        onClick={() => toggleEmailDetails(index, mail.EmailID, mail.sent, mail.received, mail)}
                                        role="button"
                                        aria-label={`Email from ${mail.Sender}, ${mail.IsRead === false ? 'unread' : 'read'}`}
                                    >
                                        <div className="email-checkbox-container">
                                            <input
                                                type="checkbox"
                                                className="email-checkbox"
                                                checked={checkedEmails.includes(mail.EmailID)}
                                                onChange={(e) => handleCheckboxChange(e, mail.EmailID)}
                                                onClick={(e) => e.stopPropagation()}
                                            />
                                        </div>
                                        <div className="email-header">
                                            <span className="email-subject">{mail.Subject}</span>
                                            <span className="email-sender">{mail.Sender}</span>
                                            <span className="email-date">{new Date(mail.SentDate).toLocaleString()}</span>

                                            {hoveredEmail === index && (
                                                <div className="email-actions">
                                                    <button
                                                        className="action-button"
                                                        title="Favorite"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleAction(mail.EmailID, 'Favorite', mail.Folder, mail.Sender, mail.Receiver);
                                                        }}
                                                    >
                                                        <FontAwesomeIcon icon={faStar} />
                                                    </button>
                                                    <button
                                                        className="action-button"
                                                        title="Trash"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleAction(mail.EmailID, 'Trash', mail.Folder, mail.Sender, mail.Receiver);
                                                        }}
                                                    >
                                                        <FontAwesomeIcon icon={faTrash} />
                                                    </button>
                                                    <button
                                                        className="action-button"
                                                        title="Archive"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleAction(mail.EmailID, 'Archive', mail.Folder, mail.Sender, mail.Receiver);
                                                        }}
                                                    >
                                                        <FontAwesomeIcon icon={faVault} />
                                                    </button>
                                                    <button
                                                        className="action-button"
                                                        title={mail.IsRead ? "Mark as Unread" : "Mark as Read"}
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            if (mail.IsRead) {
                                                                markEmailAsUnread(mail.EmailID, mail.Sender, mail.Receiver);
                                                            } else {
                                                                markEmailAsRead(mail.EmailID, mail.Sender, mail.Receiver);
                                                            }
                                                        }}
                                                    >
                                                        <FontAwesomeIcon icon={mail.IsRead ? faEnvelope : faEnvelopeOpen} />
                                                    </button>
                                                    <select
                                                        className="action-button"
                                                        title="Move to Folder"
                                                        aria-label="Move email to folder"
                                                        onClick={(e) => e.stopPropagation()}
                                                        onChange={(e) => {
                                                            if (e.target.value) {
                                                                handleMoveToFolder(mail.EmailID, e.target.value, mail.Sender, mail.Receiver);
                                                                e.target.value = '';
                                                            }
                                                        }}
                                                    >
                                                        <option value="">Move to...</option>
                                                        {customFolders.map((folder) => (
                                                            <option key={folder} value={folder}>{folder}</option>
                                                        ))}
                                                    </select>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <p>No emails found.</p>
                            )}
                        </div>
                    ) : (
                        <div className="email-fullscreen">
                            <button
                                className="mybutton"
                                onClick={() => {
                                    setSelectedEmail(null);
                                    setSelectedEmailDetails(null);
                                    setPreviewAttachment(null);
                                }}
                            >
                                <svg className="close-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                                </svg>
                            </button>
                            <div className="email-content">
                                {selectedEmailDetails ? (
                                    <>
                                        <div className="email-content-header">
                                            <h2>{selectedEmailDetails.Subject}</h2>
                                            <div className="email-header-actions">
                                                <button
                                                    className="header-action-button"
                                                    title="Delete"
                                                    onClick={() => {
                                                        handleAction(
                                                            selectedEmailDetails.EmailID,
                                                            'Trash',
                                                            selectedEmailDetails.Folder,
                                                            selectedEmailDetails.Sender,
                                                            selectedEmailDetails.Receiver
                                                        );
                                                        setSelectedEmail(null);
                                                        setSelectedEmailDetails(null);
                                                        setPreviewAttachment(null);
                                                    }}
                                                >
                                                    <svg className="action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5-4h4M9 7v12m6-12v12" />
                                                    </svg>
                                                </button>
                                                <button
                                                    className="header-action-button"
                                                    title="Favorite"
                                                    onClick={() => handleAction(
                                                        selectedEmailDetails.EmailID,
                                                        'Favorite',
                                                        selectedEmailDetails.Folder,
                                                        selectedEmailDetails.Sender,
                                                        selectedEmailDetails.Receiver
                                                    )}
                                                >
                                                    <svg className="action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.783-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                                                    </svg>
                                                </button>
                                                <button
                                                    className="header-action-button"
                                                    title="Archive"
                                                    onClick={() => handleAction(
                                                        selectedEmailDetails.EmailID,
                                                        'Archive',
                                                        selectedEmailDetails.Folder,
                                                        selectedEmailDetails.Sender,
                                                        selectedEmailDetails.Receiver
                                                    )}
                                                >
                                                    <svg className="action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                                    </svg>
                                                </button>
                                                <select
                                                    className="header-action-button"
                                                    title="Move to Folder"
                                                    aria-label="Move email to folder"
                                                    onChange={(e) => {
                                                        if (e.target.value) {
                                                            handleMoveToFolder(
                                                                selectedEmailDetails.EmailID,
                                                                e.target.value,
                                                                selectedEmailDetails.Sender,
                                                                selectedEmailDetails.Receiver
                                                            );
                                                            e.target.value = '';
                                                        }
                                                    }}
                                                >
                                                    <option value="">Move to...</option>
                                                    {customFolders.map((folder) => (
                                                        <option key={folder} value={folder}>{folder}</option>
                                                    ))}
                                                </select>
                                            </div>
                                        </div>
                                        <div className="separator"></div>
                                        <div className="email-meta">
                                            <div className="meta-info">
                                                <span className="meta-label">From:</span>
                                                <span className="meta-value">{selectedEmailDetails.Sender}</span>
                                            </div>
                                            <div className="meta-info">
                                                <span className="meta-label">To:</span>
                                                <span className="meta-value">{selectedEmailDetails.Receiver}</span>
                                            </div>
                                            <div className="meta-info">
                                                <span className="meta-label">Date:</span>
                                                <span className="meta-value">{new Date(selectedEmailDetails.SentDate).toLocaleString()}</span>
                                            </div>
                                        </div>
                                        <div className="separator"></div>
                                        <div className="email-body">
                                            <p>{selectedEmailDetails.Body}</p>
                                        </div>
                                        {selectedEmailDetails.Attachments?.length > 0 && (
                                            <>
                                                <div className="separator"></div>
                                                <div className="attachments">
                                                    <h3>Attachments</h3>
                                                    {selectedEmailDetails.Attachments.map((attachment, idx) => (
                                                        <div key={idx} className="attachment-item flex items-center space-x-2">
                                                            <span>{attachment.filename}</span>
                                                            {isPreviewable(attachment) && (
                                                                <button
                                                                    onClick={() => setPreviewAttachment(attachment)}
                                                                    className="preview-button bg-blue-500 text-white px-2 py-1 rounded hover:bg-blue-600"
                                                                    aria-label={`Preview ${attachment.filename}`}
                                                                >
                                                                    Preview
                                                                </button>
                                                            )}
                                                            <button
                                                                onClick={() => downloadAttachment(attachment)}
                                                                className="download-button"
                                                                aria-label={`Download ${attachment.filename}`}
                                                            >
                                                                Download
                                                            </button>
                                                        </div>
                                                    ))}
                                                </div>
                                            </>
                                        )}
                                    </>
                                ) : (
                                    <div className="email-loading">
                                        <div className="loading-bar subject-bar"></div>
                                        <div className="loading-bar sender-bar"></div>
                                        <div className="loading-bar receiver-bar"></div>
                                        <div className="loading-bar date-bar"></div>
                                        <div className="loading-bar body-bar"></div>
                                        <div className="loading-bar body-bar"></div>
                                        <div className="loading-bar body-bar"></div>
                                    </div>
                                )}
                            </div>
                            <ToastContainer
                                position="top-center"
                                className="custom-toast-container"
                                toastClassName="custom-toast"
                                bodyClassName="custom-toast-body"
                            />
                        </div>
                    )}
                </div>

                <div className="right-sidebar">
                    <button className="right-sidebar-button AccountPage" onClick={handleAccountPage}>
                        <FontAwesomeIcon className="icon2" icon={faUser} />
                    </button>
                    <button className="right-sidebar-button RecoveryButton" onClick={handleRecoveryPage}>
                        <FontAwesomeIcon className="icon2" icon={faShieldAlt} />
                    </button>
                    <button className="right-sidebar-button RecoveryButton" onClick={() => setIsContactsOpen(!isContactsOpen)}>
                        <FontAwesomeIcon className="icon2" icon={faAddressBook} />
                    </button>
                    <button className="right-sidebar-button RecoveryButton" onClick={() => navigate('/Info')}>
                        <FontAwesomeIcon className="icon2" icon={faQuestionCircle} />
                    </button>
                    {isAdmin && (
                        <button className="right-sidebar-button RecoveryButton" onClick={() => navigate('/AdminPannel')}>
                            <FontAwesomeIcon className="icon2" icon={faCog} />
                        </button>
                    )}
                    <button className="right-sidebar-button RecoveryButton" onClick={() => { Logout(); navigate('/Login') }}>
                        <FontAwesomeIcon className="icon2" icon={faRightFromBracket} />
                    </button>
                </div>

                <div className={`contacts-sidebar ${isContactsOpen ? 'open' : ''}`}>
                    <div className="contacts-header">
                        <h3>Contacts</h3>
                        <button
                            className="contacts-close-button"
                            onClick={() => setIsContactsOpen(false)}
                        >
                            <svg className="close-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                    <div className="contacts-content">
                        <ul className="contacts-list">
                            {contacts.map((contact) => (
                                <li key={contact.Id} className="contact-item">
                                    <div className="contact-first-row">
                                        <span className="contact-name">{contact.ContactName}</span>
                                        <button className="delete-contact">
                                            <FontAwesomeIcon
                                                className="icon-contact"
                                                icon={faEnvelope}
                                                onClick={() => { setSelectedRecipient(contact.Contact_Mail); toggleCompose(); }}
                                            />
                                        </button>
                                        <button className="delete-contact">
                                            <FontAwesomeIcon
                                                className="icon-contact"
                                                icon={faTrash}
                                                onClick={() => {
                                                    handleDeleteContact(contact.Contact_Mail);
                                                    setContacts(contacts.filter(mycontact => mycontact.Id !== contact.Id));
                                                }}
                                            />
                                        </button>
                                    </div>
                                    <span className="contact-email">{contact.Contact_Mail}</span>
                                </li>
                            ))}
                        </ul>
                        <button className="add-contact-button" onClick={() => setShowEmailModal(!showEmailModal)}>
                            <FontAwesomeIcon className="add-contact-icon" icon={faPlus} />
                            <span className="add-contact-label">Add Contact</span>
                        </button>
                    </div>
                </div>

                {showEmailModal && (
                    <div className="EmailModal">
                        <div className="email-modal-content">
                            <span className="close-modal-email" onClick={() => setShowEmailModal(false)}>�</span>
                            <h2>Enter New Contact</h2>
                            <input
                                type="email"
                                name="email"
                                value={newEmail}
                                onChange={(e) => setNewEmail(e.target.value)}
                                placeholder="Email"
                                className="emailmodalinput"
                            />
                            <button
                                className="applybuttonemailmodel"
                                onClick={() => { handleAddContact(newEmail); setShowEmailModal(false); }}
                            >
                                Add Contact
                            </button>
                        </div>
                    </div>
                )}

                {previewAttachment && <AttachmentPreview attachment={previewAttachment} />}
            </div>

            {isComposeOpen && (
                <ComposeEmail
                    onClose={() => toggleCompose()}
                    initialRecipient={selectedRecipient}
                    onError={handleChildError}
                />
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

export default Inbox;