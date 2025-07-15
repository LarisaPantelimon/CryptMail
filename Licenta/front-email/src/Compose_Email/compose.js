import React, { useState, useEffect, useContext } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPaperclip, faImage, faLink, faTimes } from '@fortawesome/free-solid-svg-icons';
import './compose.css';
import MimeBuilder from 'emailjs-mime-builder';
import CryptoJS from 'crypto-js'; // For AES encryption
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { AuthContext } from '../Login/AuthContext';
import forge from 'node-forge'; // For PKCS8 PEM decryption

import {
    buildMessageStructure,
    buildSignaturePart,
    buildBlobForZip,
    compressMessage,
    encryptAesGcm,
    encryptSymmetricKeyWithRsa,
    encryptedSymmetricKey,
    constructFinalFormOfMessage
} from './encryption'; 


function ComposeEmail({ onClose, initialRecipient = '' ,onError }) {
    const [recipients, setRecipients] = useState(initialRecipient ? [initialRecipient] : []);
    const [inputValue, setInputValue] = useState("");
    const [subject, setSubject] = useState('');
    const [body, setBody] = useState('');
    const [showLinkModal, setShowLinkModal] = useState(false);
    const [linkText, setLinkText] = useState('');
    const [linkUrl, setLinkUrl] = useState('');
    const [email, setEmail] = useState('');
    const [attachments, setAttachments] = useState([]); // Store multiple files
    const [isSending, setIsSending] = useState(false);
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);

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
                if(data.PublicKey===null) {
                    if(receiverEmail===email)
                        {toast.error("Your Public Key is expired! Please generate a new one from the Profile Settings!"); return;}
                    else
                        {toast.error("The receiver's Public Key is expired! Try again later."); return;}}
                return { public_key: data.PublicKey,key_id: data.KeyId }; 
            } else {
                throw new Error(data.error || "Failed to fetch receiver's public key");
            }
        } catch (error) {
            //console.error("Error fetching receiver's public key:", error);
            throw error;
        }
    };
 
    const handleAddRecipient = (e) => {
        if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
            e.preventDefault();
            const email = inputValue.trim();
            if (email && !recipients.includes(email)) {
                setRecipients([...recipients, email]);
                setInputValue('');
            }
        }
    };    

    const removeRecipient = (index) => {
        setRecipients(recipients.filter((_, i) => i !== index));
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
                    //console.error("Failed to retrieve email:", data.error);
                }
            } catch (error) {
                //console.error("Error:", error);
            }
        };
        
        fetchUserEmail();
    }, []);

    const handleInsertLink = () => {
        if (linkText && linkUrl) {
            const linkMarkup = `[${linkText}](${linkUrl})`; // Markdown-style link
            setBody((prevBody) => prevBody + ` ${linkMarkup}`);
            setShowLinkModal(false);
            setLinkText("");
            setLinkUrl("");
        }
    };
    

    const MAX_ATTACHMENT_SIZE_MB = 18;

    const handleAttachment = (event) => {
        const files = Array.from(event.target.files);
        const totalSize = attachments.reduce((sum, file) => sum + file.size, 0) + 
                        files.reduce((sum, file) => sum + file.size, 0);

        if (totalSize > MAX_ATTACHMENT_SIZE_MB * 1024 * 1024) {
            alert("Total attachment size exceeds 18 MB. Please remove some files or select smaller ones.");
            return;
        }

        setAttachments(prevAttachments => [...prevAttachments, ...files]); // Append new files
    };

    const handleRemoveAttachment = (index) => {
        setAttachments(prevAttachments => 
            prevAttachments.filter((_, i) => i !== index) // Remove the file at the specified index
        );
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

    const decryptWithPassword = (encryptedPrivateKey, password) => {
            try {
                if (typeof encryptedPrivateKey !== 'string' || encryptedPrivateKey.length === 0) {
                    throw new Error("Encrypted private key is not in a valid format.");
                }
        
                // Attempt decryption
                const privateKey = forge.pki.decryptRsaPrivateKey(encryptedPrivateKey, password);

                if (!privateKey) {
                    throw new Error("Decryption failed. Incorrect password or corrupted data.");
                }
        
                // Return the decrypted private key
                const decryptedPrivateKeyPem = forge.pki.privateKeyToPem(privateKey);
                return decryptedPrivateKeyPem;
        
            } catch (error) {
                //console.error("Decryption error:", error.message);
                //console.error("Encrypted Private Key (trimmed for privacy):", encryptedPrivateKey.slice(0, 100)); // Log first 100 chars to avoid sensitive info exposure
                //console.error("Password (trimmed for privacy):", password.slice(0, 3) + '***'); // Log a portion of password for debugging (don't expose the full password!)
                throw new Error("Failed to decrypt private key. Please check your password and try again.");
            }
        };
    const fetchMyPrvKey = async (email,keyId) => {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        try {
            const response = await fetchWithAuth('/api/get-myprivatekey', {
                method: 'POST',
                credentials: 'include', // Sends access_token cookie
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // Include CSRF token
                },
                body: JSON.stringify({ email: email, key_id: keyId }),
            });

            const data = await response.json();
            if (response.ok) {
                //console.log("Private Key from backend:", data.PrivateKey);
                return data.PrivateKey;
            } else {
                throw new Error(data.error || "Failed to fetch private key");
            }
        } catch (error) {
            //console.error("Error fetching private key:", error);
            throw error;
        }
    };

    async function handleSendEmail(recipients) {
        if (!recipients || !subject || !body) {
            alert("Please fill in recipient, subject, and body.");
            return;
        }
        if (isSending) return; // Prevent multiple clicks
        setIsSending(true);
    
        const emailPromises = recipients.map(async (recipient) => {
            const mime = new MimeBuilder('multipart/mixed')
                .setHeader('From', email)
                .setHeader('To', recipient)
                .setHeader('Subject', subject);
    
            mime.createChild('text/plain').setContent(body);
    
            const attachmentPromises = attachments.map(file => {
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => {
                        const binaryData = reader.result; // ArrayBuffer
                        const uint8Data = new Uint8Array(binaryData); // Convert to Uint8Array
                        // console.log(`Attachment ${file.name}:`, {
                        //     size: uint8Data.length,
                        //     type: file.type
                        // });
                        mime.createChild('application/octet-stream')
                            .setHeader('Content-Disposition', `attachment; filename="${file.name}"`)
                            .setHeader('Content-Transfer-Encoding', 'base64')
                            .setContent(uint8Data);
                        resolve();
                    };
                    reader.onerror = reject;
                    reader.readAsArrayBuffer(file);
                });
            });
    
            await Promise.all(attachmentPromises);
    
            const { public_key, key_id } = await fetchReceiverKey(recipient);
            const mimeMessage = mime.build(); // Returns ASCII string

            // console.log("MIME Message:", mimeMessage); // Log first 500 chars
            ////console.log("MIME Message Size:", mimeMessage.length);
    
            const encryptedPassword = sessionStorage.getItem('x7k9p2m');
            if (!encryptedPassword) {
                throw new Error("Encrypted password not found. Please log in again.");
            }
    
            const sessionKey = await fetchSessionKey();
            const { public_key: senderPublicKey, key_id: senderKeyId, ExpirationDate:exp } = await fetchReceiverKey(email);
            //console.log(senderKeyId);
            //console.log(exp);
            const private_key = await fetchMyPrvKey(email, senderKeyId);
    
            let decryptedPassword = CryptoJS.AES.decrypt(encryptedPassword, sessionKey).toString(CryptoJS.enc.Utf8);
            if (!decryptedPassword) {
                throw new Error("Failed to decrypt private key. Please check your session key.");
            }
    
            let decryptedPrivateKey = decryptWithPassword(private_key, decryptedPassword);
    
            const messageStructure = await buildMessageStructure(mimeMessage);
            const signaturePart = await buildSignaturePart(messageStructure, senderKeyId, decryptedPrivateKey);
            const blobForZip = await buildBlobForZip(messageStructure, signaturePart);
            const compressedData = await compressMessage(blobForZip);
            const { ciphertext, encryptionParams } = await encryptAesGcm(compressedData);
    
            const encryptedSymmetricKeyV = await encryptSymmetricKeyWithRsa(encryptionParams, public_key);
            const blobSymmetricKey = encryptedSymmetricKey(key_id, encryptedSymmetricKeyV);
            const finalMessage = constructFinalFormOfMessage(blobSymmetricKey, ciphertext);
    
            const encryptedSymmetricKeyForMe = await encryptSymmetricKeyWithRsa(encryptionParams, senderPublicKey);
            const blobSymmetricKeyForMe = encryptedSymmetricKey(senderKeyId, encryptedSymmetricKeyForMe);
            const finalMessageForMe = constructFinalFormOfMessage(blobSymmetricKeyForMe, ciphertext);
    
            decryptedPrivateKey = null;
    
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];
    
            try {
                const response = await fetchWithAuth('/api/inbox/send-email', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                    body: JSON.stringify({
                        from: email,
                        to: recipient,
                        mime_message: finalMessage, // Base64 string
                        mime_message_for_me: finalMessageForMe, // Base64 string
                        subject: subject
                    })
                });
    
                const data = await response.json();
                if (response.ok) {
                    // toast.success("Email sent successfully");
                    onClose();
                } else {
                    alert("Failed to send email:", data.error);
                }
            } catch (error) {
                alert("Error sending email:", error);
            }
        });
    
        try {
            await Promise.all(emailPromises);
            removeAllRecipients(); // Clear recipients after sending
            onClose();
        } catch (error) {
            //console.error("Error sending emails:", error);
        }
    }

    const removeAllRecipients = () => {
        setRecipients([]);
        setInputValue('');
    };
    
      // Modified onClose handler to clear recipients before closing
    const handleClose = () => {
        removeAllRecipients();
        onClose(); // Call the parent's onClose to close the component
    };

    return (
        <div className="compose-email-overlay">
            <div className="compose-email-window">
                <div className="compose-header">
                    <span>New Message</span>
                    <button onClick={handleClose} className="close-button">×</button>
                </div>
                <form onSubmit={(e) => e.preventDefault()}>
                    {/* Multi-recipient input */}
                    <div className="recipient-container">
                        {recipients.map((email, index) => (
                            <div key={index} className="email-chip">
                                {email}
                                <FontAwesomeIcon
                                    icon={faTimes}
                                    onClick={() => removeRecipient(index)}
                                    className="remove-icon"
                                />
                            </div>
                        ))}
                        <input
                            type="email"
                            placeholder="Recipients"
                            value={inputValue}
                            onChange={(e) => setInputValue(e.target.value)}
                            onKeyDown={handleAddRecipient}
                            className="compose-input"
                            disabled={isSending} // Disable input while sending
                        />
                    </div>

                    <input
                        type="text"
                        placeholder="Subject"
                        value={subject}
                        onChange={(e) => setSubject(e.target.value)}
                        className="compose-input2"
                        disabled={isSending} // Disable input while sending
                    />
                    <textarea
                        placeholder="Message"
                        className="compose-textarea"
                        value={body}
                        onChange={(e) => setBody(e.target.value)}
                        disabled={isSending} // Disable textarea while sending
                    />

                    <div className="compose-footer">
                        <button
                            type="button"
                            className="send-button"
                            onClick={async () => await handleSendEmail(recipients)}
                            disabled={isSending} // Disable button while sending
                        >
                            {isSending ? 'Sending...' : 'Send'}
                        </button>
                        <div className="icon-group">
                            <label>
                                <FontAwesomeIcon icon={faPaperclip} />
                                <input
                                    type="file"
                                    multiple
                                    onChange={handleAttachment}
                                    style={{ display: 'none' }}
                                    disabled={isSending} // Disable file input while sending
                                />
                            </label>
                            <label>
                                <FontAwesomeIcon icon={faImage} />
                                <input
                                    type="file"
                                    accept="image/*"
                                    multiple
                                    onChange={handleAttachment}
                                    style={{ display: 'none' }}
                                    disabled={isSending} // Disable file input while sending
                                />
                            </label>
                            <FontAwesomeIcon
                                icon={faLink}
                                onClick={() => setShowLinkModal(true)}
                                className="link-icon"
                                style={{ pointerEvents: isSending ? 'none' : 'auto' }} // Disable link icon while sending
                            />
                        </div>
                    </div>

                    <div className="selected-files">
                        {attachments.length > 0 && (
                            <ul>
                                {attachments.map((file, index) => (
                                    <li className="listOfFiles" key={index}>
                                        {file.name}
                                        <button
                                            type="button"
                                            onClick={() => handleRemoveAttachment(index)}
                                            className="remove-file-button"
                                            disabled={isSending} // Disable remove button while sending
                                        >
                                            ×
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </form>

                {/* Link Modal */}
                {showLinkModal && (
                    <div className="link-modal">
                        <div className="link-modal-content">
                            <input
                                type="text"
                                placeholder="Text to display"
                                value={linkText}
                                onChange={(e) => setLinkText(e.target.value)}
                                className="link-input"
                                disabled={isSending} // Disable input while sending
                            />
                            <input
                                type="url"
                                placeholder="URL"
                                value={linkUrl}
                                onChange={(e) => setLinkUrl(e.target.value)}
                                className="link-input"
                                disabled={isSending} // Disable input while sending
                            />
                            <div className="link-modal-buttons">
                                <button
                                    onClick={() => setShowLinkModal(false)}
                                    className="cancel-button"
                                    disabled={isSending} // Disable cancel button while sending
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleInsertLink}
                                    className="apply-button"
                                    disabled={isSending} // Disable apply button while sending
                                >
                                    Apply
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export default ComposeEmail;