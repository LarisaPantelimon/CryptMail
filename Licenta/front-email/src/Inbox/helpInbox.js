import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export const getContacts = async () => {
    try {
        const response = await fetch('/api/inbox/get-contacts', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (response.ok) {
            return data.contacts;
        } else {
            //console.error('Error fetching contacts:', data);
            toast.error(data.error || 'Failed to fetch contacts');
            return [];
        }
    } catch (error) {
        //console.error('Error:', error);
        toast.error('An error occurred while fetching contacts');
        return [];
    }
}

export const handleAddContact = async (contact) => {
    try{
        const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];
        const response = await fetch('/api/inbox/add-contact', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(contact)
        })
        const data = await response.json()
        if (response.ok) {
            ////console.log('Contact added successfully:', data);
            // Optionally, you can update the UI or show a success message here
        } else {
            //console.error('Error adding contact:', data);
            // Optionally, you can show an error message to the user here
            toast.error(data.error || 'Failed to add contact');
        }
    }
    catch (error) {
        //console.error('Error:', error);
        toast.error('An error occurred while adding the contact');
    }
}

export const handleDeleteContact = async (contactMail) => {
    try {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        const response = await fetch('/api/inbox/delete-contact', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(contactMail)
        });
        const data = await response.json();
        if (response.ok) {
            ////console.log('Contact deleted successfully:', data);
            // Optionally, you can update the UI or show a success message here
            toast.success('Contact deleted successfully');
        } else {
            //console.error('Error deleting contact:', data);
            // Optionally, you can show an error message to the user here
            toast.error(data.error || 'Failed to delete contact');
        }
    } catch (error) {
        //console.error('Error:', error);
        toast.error('An error occurred while deleting the contact');
    }
}
export const fetchCustomFolders = async () => {
    try {
        const csrfToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_access_token='))
            ?.split('=')[1];
        const response = await fetch('/api/inbox/get-folders', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
        });
        const data = await response.json();
        if (response.ok) {
            return data.folders.map(folder => folder.FolderName) || [];
        } else {
            //console.error('Error fetching custom folders:', data);
            toast.error(data.error || 'Failed to fetch custom folders');
            return [];
        }
    } catch (error) {
        //console.error('Error:', error);
        toast.error('An error occurred while fetching custom folders');
        return [];
    }
}
