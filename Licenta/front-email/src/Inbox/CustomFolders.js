import React, { useState, useContext } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFolder, faPlus, faTrash } from '@fortawesome/free-solid-svg-icons';
import './CustomFolders.css';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { AuthContext } from '../Login/AuthContext';

const CustomFolders = ({ selectCategory, selectedCategory, customFolders, setCustomFolders }) => {
    const [showAddFolderModal, setShowAddFolderModal] = useState(false);
    const [newFolderName, setNewFolderName] = useState('');
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);

    const getCsrfToken = () => {
        return document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
    };

    const handleAddFolder = async () => {
        const folderName = newFolderName.trim();
        if (!folderName || customFolders.includes(folderName)) {
            toast.error('Folder name is invalid or already exists.');
            return;
        }

        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            toast.error('CSRF token not found. Please try again.');
            return;
        }

        try {
            const response = await fetch('/api/inbox/add-folder', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify(folderName),
            });

            if (!response.ok) {
                throw new Error('Failed to add folder.');
            }

            setCustomFolders([...customFolders, folderName]);
            setNewFolderName('');
            setShowAddFolderModal(false);
            toast.success('Folder added successfully!');
        } catch (error) {
            //console.error('Error adding folder:', error);
            toast.error('An error occurred while adding the folder.');
        }
    };

    const handleDeleteFolder = async (folderName) => {
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            toast.error('CSRF token not found. Please try again.');
            return;
        }

        try {
            const response = await fetch('/api/inbox/delete-folder', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify(folderName),
            });

            if (!response.ok) {
                throw new Error('Failed to delete folder.');
            }

            setCustomFolders(customFolders.filter((folder) => folder !== folderName));
            if (selectedCategory === folderName) {
                selectCategory('Inbox');
            }
            toast.success('Folder deleted successfully!');
        } catch (error) {
            //console.error('Error deleting folder:', error);
            toast.error('An error occurred while deleting the folder.');
        }
    };

    return (
        <div className="custom-folders">
            <div className="custom-folders-header">
                <span>Your Folders</span>
                <button
                    className="add-folder-button"
                    onClick={() => setShowAddFolderModal(true)}
                    title="Add New Folder"
                >
                    <FontAwesomeIcon icon={faPlus} />
                </button>
            </div>
            <ul className="custom-folders-list">
                {customFolders.map((folder) => (
                    <li
                        key={folder}
                        className={`custom-folder-item ${selectedCategory === folder ? 'active' : ''}`}
                        onClick={() => selectCategory(folder)}
                    >
                        <FontAwesomeIcon className="icon" icon={faFolder} />
                        <span className="folder-text">{folder}</span>
                        <button
                            className="delete-folder-button"
                            onClick={(e) => {
                                e.stopPropagation();
                                handleDeleteFolder(folder);
                            }}
                            title={`Delete ${folder}`}
                        >
                            <FontAwesomeIcon icon={faTrash} />
                        </button>
                    </li>
                ))}
            </ul>

            {showAddFolderModal && (
                <div className="add-folder-modal">
                    <div className="modal-content">
                        <span
                            className="close-modal"
                            onClick={() => setShowAddFolderModal(false)}
                            aria-label="Close modal"
                        >
                            &times;
                        </span>
                        <h3>Add New Folder</h3>
                        <input
                            type="text"
                            value={newFolderName}
                            onChange={(e) => setNewFolderName(e.target.value)}
                            placeholder="Folder Name"
                            className="folder-input"
                        />
                        <button
                            className="add-folder-submit"
                            onClick={handleAddFolder}
                            disabled={!newFolderName.trim()}
                        >
                            Add Folder
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CustomFolders;