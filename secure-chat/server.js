const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

app.use(express.static(path.join(__dirname, 'public')));

// Lưu danh sách người dùng online: { username: { socketId, publicKey } }
const users = {};

io.on('connection', (socket) => {
    // 1. Đăng ký tài khoản / kết nối
    socket.on('register_user', ({ username, publicKey }) => {
        socket.username = username;
        users[username] = {
            socketId: socket.id,
            publicKey: publicKey
        };
        
        // Phát danh sách user online cho mọi người
        io.emit('update_user_list', Object.keys(users));
    });

    // 2. Yêu cầu lấy Public Key RSA của người nhận
    socket.on('get_public_key', (targetUsername, callback) => {
        if (users[targetUsername]) {
            callback({ success: true, publicKey: users[targetUsername].publicKey });
        } else {
            callback({ success: false, message: 'Người dùng không trực tuyến' });
        }
    });

    // 3. Chuyển tiếp tin nhắn đã mã hóa
    socket.on('send_secure_message', (data) => {
        const { receiverUsername } = data;
        if (users[receiverUsername]) {
            io.to(users[receiverUsername].socketId).emit('receive_secure_message', data);
        }
    });

    // 4. Xử lý ngắt kết nối
    socket.on('disconnect', () => {
        if (socket.username && users[socket.username]) {
            delete users[socket.username];
            io.emit('update_user_list', Object.keys(users));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server đang chạy tại port ${PORT}`);
});