const io = require('socket.io-client');
const socket = io('https://cryptmail.stud.fsisc.ro/mobile/', {
    path: '/mobile/socket.io/',
    transports: ['websocket'],
    forceNew: true
});

socket.on('connect', () => {
    console.log('Connected');
    socket.emit('ping');
});

socket.on('pong', (data) => {
    console.log('Received:', data);
});

socket.on('connect_error', (err) => {
    console.error('Connection error:', err.message);
});

socket.on('disconnect', () => {
    console.log('Disconnected');
});
