import React, { useState, useEffect, useRef, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import Chart from 'chart.js/auto';
import { faInbox, faShieldAlt, faCog, faUser, faQuestionCircle, faBars } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import './AdminPannel.css';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import logo from '../ImgSrc/logoWhite.png';
import { AuthContext } from '../Login/AuthContext';

const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
};

const AdminPannel = () => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [logSearchTerm, setLogSearchTerm] = useState('');
    const [userSearchTerm, setUserSearchTerm] = useState('');
    const [allUsers, setAllUsers] = useState([]); // Store all users
    const [displayedUsers, setDisplayedUsers] = useState([]); // Users to display
    const [allLogs, setAllLogs] = useState([]);
    const [displayedLogs, setDisplayedLogs] = useState([]);
    const [currentLogPage, setCurrentLogPage] = useState(1);
    const logsPerPage = 10; // Number of logs per page
    const [currentUserPage, setCurrentUserPage] = useState(1);
    const usersPerPage = 10; // Number of users per page
    const [userData, setUserData] = useState([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const [totalUsers, setTotalUsers] = useState(0);
    const [totalSentEmails, setTotalSentEmails] = useState(0);
    const [total2FAUsers, setTotal2FAUsers] = useState(0);
    const chartRef = useRef(null);
    const navigate = useNavigate();
    const { fetchWithAuth, isAuthenticated, isAdmin } = useContext(AuthContext);

    // Fetch admin info
    useEffect(() => {
        const fetchAdminInfo = async () => {
            try {
                const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];

                const response = await fetchWithAuth('/api/admin-info', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch admin info');
                }

                const data = await response.json();

                if (data.success) {
                    setTotalUsers(data.total_users || 0);
                    setTotalSentEmails(data.total_sent_emails || 0);
                    setTotal2FAUsers(data.total_2fa_users || 0);
                    setUserData(data.user_data || [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                } else {
                    //console.error('Error from backend:', data.error);
                }
            } catch (error) {
                //console.error('Error fetching admin info:', error);
            }
        };

        fetchAdminInfo();
    }, []);

    // Fetch logs
    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];

                const response = await fetchWithAuth('/api/admin-get-logs', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch logs');
                }

                const data = await response.json();

                if (data.success) {
                    const fetchedLogs = data.logs || [];
                    setAllLogs(fetchedLogs);
                    setDisplayedLogs(fetchedLogs.slice(0, logsPerPage));
                } else {
                    //console.error('Error from backend:', data.error);
                }
            } catch (error) {
                //console.error('Error fetching logs:', error);
            }
        };

        fetchLogs();
    }, []);

    // Fetch users
    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const csrfToken = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrf_access_token='))
                    ?.split('=')[1];

                const response = await fetchWithAuth('/api/admin-get-users', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                    },
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch users');
                }

                const data = await response.json();

                if (data.success) {
                    const fetchedUsers = data.users || [];
                    setAllUsers(fetchedUsers);
                    setDisplayedUsers(fetchedUsers.slice(0, usersPerPage));
                } else {
                    //console.error('Error from backend:', data.error);
                }
            } catch (error) {
                //console.error('Error fetching users:', error);
            }
        };

        fetchUsers();
    }, []);

    // Update displayed logs based on search term and current page
    useEffect(() => {
        const filtered = allLogs.filter(log =>
            log.UserEmail.toLowerCase().includes(logSearchTerm.toLowerCase()) ||
            log.ActionName.toLowerCase().includes(logSearchTerm.toLowerCase())
        );

        const startIndex = (currentLogPage - 1) * logsPerPage;
        const endIndex = startIndex + logsPerPage;
        setDisplayedLogs(filtered.slice(startIndex, endIndex));
    }, [logSearchTerm, allLogs, currentLogPage]);

    // Update displayed users based on search term and current page
    useEffect(() => {
        const filtered = allUsers.filter(user =>
            user.email.toLowerCase().includes(userSearchTerm.toLowerCase()) ||
            user.fullName.toLowerCase().includes(userSearchTerm.toLowerCase())
        );

        const startIndex = (currentUserPage - 1) * usersPerPage;
        const endIndex = startIndex + usersPerPage;
        setDisplayedUsers(filtered.slice(startIndex, endIndex));
    }, [userSearchTerm, allUsers, currentUserPage]);

    // Calculate total pages for logs pagination
    const filteredLogs = allLogs.filter(log =>
        log.UserEmail.toLowerCase().includes(logSearchTerm.toLowerCase()) ||
        log.ActionName.toLowerCase().includes(logSearchTerm.toLowerCase())
    );
    const totalLogPages = Math.ceil(filteredLogs.length / logsPerPage);

    const handleLogPageChange = (page) => {
        if (page >= 1 && page <= totalLogPages) {
            setCurrentLogPage(page);
        }
    };

    // Calculate total pages for users pagination
    const filteredUsers = allUsers.filter(user =>
        user.email.toLowerCase().includes(userSearchTerm.toLowerCase()) ||
        user.fullName.toLowerCase().includes(userSearchTerm.toLowerCase())
    );
    const totalUserPages = Math.ceil(filteredUsers.length / usersPerPage);

    const handleUserPageChange = (page) => {
        if (page >= 1 && page <= totalUserPages) {
            setCurrentUserPage(page);
        }
    };

    const toggleUser = async (email) => {
        const userToToggle = allUsers.find(user => user.email === email);
        if (!userToToggle) return; // User not found
        if (userToToggle.enabled) {
        setAllUsers(allUsers.map(user =>
            user.email === email ? { ...user, enabled: !user.enabled } : user
        ));
        try {
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];

            const response = await fetchWithAuth('/api/admin-disable-2fa', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify(email),
            });

            const data = await response.json();
            if (data.error) {
                toast.error('Failed to toggle user 2FA status');
                setAllUsers(allUsers.map(user =>
                    user.email === email ? { ...user, enabled: !user.enabled } : user
                ));
            }
        } catch (error) {
            //console.error('Error toggling user 2FA status:', error);
            toast.error('Error toggling user 2FA status');
            setAllUsers(allUsers.map(user =>
                user.email === email ? { ...user, enabled: !user.enabled } : user
            ));
        }
    }
    };

    const deleteUser = async (email) => {
        const updatedUsers = allUsers.filter(user => user.email !== email);
        setAllUsers(updatedUsers);
        try {
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf_access_token='))
                ?.split('=')[1];

            const response = await fetchWithAuth('/api/admin-delete-user', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify(email),
            });

            const data = await response.json();
            if (data.error) {
                toast.error('Failed to delete user');
                setAllUsers(allUsers);
            }
        } catch (error) {
            //console.error('Error deleting user:', error);
            toast.error('Error deleting user');
            setAllUsers(allUsers);
        }
    };

    useEffect(() => {
        const ctx = document.getElementById('usersChart')?.getContext('2d');
        if (ctx) {
            if (chartRef.current) {
                chartRef.current.destroy();
            }

            chartRef.current = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                    datasets: [{
                        label: 'New Users',
                        data: userData,
                        backgroundColor: '#0d0686',
                        borderColor: '#0d0686',
                        borderWidth: 0,
                        barThickness: 15,
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: '#e5e7eb',
                                drawBorder: false,
                                drawTicks: false,
                            },
                            ticks: {
                                color: '#9ca3af',
                                font: {
                                    size: 12
                                },
                                padding: 10,
                            },
                            max: Math.max(...userData, 70),
                        },
                        x: {
                            grid: {
                                display: false,
                                drawBorder: false,
                            },
                            ticks: {
                                color: '#9ca3af',
                                font: {
                                    size: 12
                                },
                                padding: 10,
                            },
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        return () => {
            if (chartRef.current) {
                chartRef.current.destroy();
                chartRef.current = null;
            }
        };
    }, [userData]);

    return (
        <div className="adminPage">
            <ToastContainer position="top-center" autoClose={3000} hideProgressBar={false} newestOnTop={false} closeOnClick pauseOnHover />
            <button 
                className="toggle-btn"
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            >
                <i className={`fas ${isSidebarOpen ? 'fa-times' : 'fa-bars'}`}></i>
            </button>
            <div className={`sidebar-admin ${isSidebarOpen ? 'open' : ''}`}>
                {isSidebarOpen && (
                    <div className="sidebar-admin-header">
                        <div className="sidebar-admin-logo">
                            <img src={logo} alt="CryptMail Logo" />
                        </div>
                    </div>
                )}
                <ul className={`sidebar-menu-admin ${isSidebarOpen ? 'open' : 'closed'}`}>
                    <li className="sidebar-info-admin">
                        <button
                            className="sidebar-button-admin"
                            onClick={() => navigate('/Inbox')}
                            title="Inbox"
                            aria-label="Navigate to Inbox"
                        >
                            <FontAwesomeIcon icon={faInbox} className="sidebar-icon-admin" />
                            <span className="sidebar-text-admin">Inbox</span>
                        </button>
                    </li>
                    <li className="sidebar-info-admin">
                        <button
                            className="sidebar-button-admin"
                            onClick={() => navigate('/Account')}
                            title="Account Settings"
                            aria-label="Navigate to Account Settings"
                        >
                            <FontAwesomeIcon icon={faUser} className="sidebar-icon-admin" />
                            <span className="sidebar-text-admin">Account Settings</span>
                        </button>
                    </li>
                    <li className="sidebar-info-admin">
                        <button
                            className="sidebar-button-admin"
                            onClick={() => navigate('/Recovery')}
                            title="Recovery Data"
                            aria-label="Navigate to Recovery Data"
                        >
                            <FontAwesomeIcon icon={faShieldAlt} className="sidebar-icon-admin" />
                            <span className="sidebar-text-admin">Recovery Data</span>
                        </button>
                    </li>
                    <li className="sidebar-info-admin">
                        <button
                            className="sidebar-button-admin"
                            onClick={() => navigate('/info')}
                            title="Info Page"
                            aria-label="Navigate to Info Page"
                        >
                            <FontAwesomeIcon icon={faQuestionCircle} className="sidebar-icon-admin" />
                            <span className="sidebar-text-admin">Info Page</span>
                        </button>
                    </li>
                    <li className="active-dash">
                        <button
                            className="sidebar-button-admin active"
                            onClick={() => navigate('/AdminPannel')}
                            title="Dashboard"
                            aria-label="Navigate to Dashboard"
                        >
                            <FontAwesomeIcon icon={faCog} className="sidebar-icon-admin" />
                            <span className="sidebar-text-admin">Dashboard</span>
                        </button>
                    </li>
                </ul>
            </div>
            <div className={`main-content ${isSidebarOpen ? 'open' : ''}`}>
                <div className="stat-cards-container">
                    <div className="stat-card">
                        <i className="fas fa-users"></i>
                        <div>
                            <p>Total # Users</p>
                            <p>{formatNumber(totalUsers)}</p>
                        </div>
                    </div>
                    <div className="stat-card">
                        <i className="fas fa-mobile-alt"></i>
                        <div>
                            <p>Total # Users 2FA</p>
                            <p>{formatNumber(total2FAUsers)}</p>
                        </div>
                    </div>
                    <div className="stat-card">
                        <i className="fas fa-envelope"></i>
                        <div>
                            <p>Total # Emails</p>
                            <p>{formatNumber(totalSentEmails)}</p>
                        </div>
                    </div>
                </div>
                <div className="chart-and-users-container">
                    <div className="users-per-month">
                        <p>Nr of Users Per Month</p>
                        <ul>
                            {['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].map((month, index) => (
                                <li key={month}>{month}: {userData[index]}</li>
                            ))}
                        </ul>
                    </div>
                    <div className="chart-container">
                        <canvas id="usersChart"></canvas>
                    </div>
                </div>
                <div className="tables-container">
                    <div className="list-container">
                        <input
                            type="text"
                            placeholder="Search bar"
                            value={logSearchTerm}
                            onChange={(e) => {
                                setLogSearchTerm(e.target.value);
                                setCurrentLogPage(1);
                            }}
                        />
                        <table>
                            <thead>
                                <tr>
                                    <th>email_user</th>
                                    <th>action</th>
                                    <th>time</th>
                                    <th>date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {displayedLogs.slice().reverse().map((log, index) => (
                                    <tr key={index}>
                                        <td>{log.UserEmail}</td>
                                        <td>{log.ActionName}</td>
                                        <td>{log.LogTime}</td>
                                        <td>{log.LogDate}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        <div className="pagination">
                            <button
                                onClick={() => handleLogPageChange(currentLogPage - 1)}
                                disabled={currentLogPage === 1}
                            >
                                Previous
                            </button>
                            <span>Page {currentLogPage} of {totalLogPages}</span>
                            <button
                                onClick={() => handleLogPageChange(currentLogPage + 1)}
                                disabled={currentLogPage === totalLogPages}
                            >
                                Next
                            </button>
                        </div>
                    </div>
                    <div className="list-container">
                        <input
                            type="text"
                            placeholder="Search bar"
                            value={userSearchTerm}
                            onChange={(e) => {
                                setUserSearchTerm(e.target.value);
                                setCurrentUserPage(1);
                            }}
                        />
                        <table>
                            <thead>
                                <tr>
                                    <th>Users</th>
                                    <th>Full_Name</th>
                                    <th>Delete</th>
                                    <th>En/Dis 2FA</th>
                                </tr>
                            </thead>
                            <tbody>
                                {displayedUsers.map(user => (
                                    <tr key={user.email}>
                                        <td>{user.email}</td>
                                        <td>{user.fullName}</td>
                                        <td>
                                            <button
                                                onClick={() => deleteUser(user.email)}
                                                className="text-red-500"
                                            >
                                                D
                                            </button>
                                        </td>
                                        <td>
                                            <button
                                                onClick={() => toggleUser(user.email)}
                                                className={user.enabled ? 'bg-green-500' : 'bg-gray-500'}
                                            >
                                                {user.enabled ? 'On' : 'Off'}
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        <div className="pagination">
                            <button
                                onClick={() => handleUserPageChange(currentUserPage - 1)}
                                disabled={currentUserPage === 1}
                            >
                                Previous
                            </button>
                            <span>Page {currentUserPage} of {totalUserPages}</span>
                            <button
                                onClick={() => handleUserPageChange(currentUserPage + 1)}
                                disabled={currentUserPage === totalUserPages}
                            >
                                Next
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AdminPannel;