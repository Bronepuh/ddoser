import { io } from 'socket.io-client';

const socket = io(import.meta.env.VITE_SOCKET_URL!, {
  path: '/ddoser/socket.io',
  transports: ['websocket'],
});

socket.on('connect', () => {
  console.log('Socket.IO connected!', socket.id);
});

socket.on('stats', (data) => {
  console.log('Stats:', data);
});

export default socket;
