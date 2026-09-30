const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public'));

const registeredUsers = {}; // { username: { passwordHash, publicKey, signPublicKey } }
const onlineUsers = {};     // { username: socketId }

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

io.on('connection', (socket) => {

    // Xử lý Đăng ký
    socket.on('register_account', (data, callback) => {
        const { username, password, publicKey, signPublicKey } = data;
        
        if (registeredUsers[username]) {
            return callback({ success: false, message: 'Tên tài khoản đã tồn tại!' });
        }

        registeredUsers[username] = {
            passwordHash: hashPassword(password),
            publicKey: publicKey,
            signPublicKey: signPublicKey
        };

        callback({ success: true, message: 'Đăng ký thành công! Vui lòng chuyển sang Đăng nhập.' });
    });

    // Xử lý Đăng nhập
    socket.on('login_account', (data, callback) => {
        const { username, password, publicKey, signPublicKey } = data;
        const user = registeredUsers[username];

        if (!user || user.passwordHash !== hashPassword(password)) {
            return callback({ success: false, message: 'Tài khoản hoặc mật khẩu không đúng!' });
        }

        // Cập nhật thông tin phiên mới
        user.publicKey = publicKey;
        user.signPublicKey = signPublicKey;

        // Lưu Socket ID
        onlineUsers[username] = socket.id;
        socket.username = username;

        callback({ success: true, message: 'Đăng nhập thành công!' });

        // Phát danh sách mới cho TẤT CẢ client đang kết nối ngay lập tức
        io.emit('update_user_list', Object.keys(onlineUsers));
    });

    // Client chủ động xin danh sách online
    socket.on('request_user_list', () => {
        socket.emit('update_user_list', Object.keys(onlineUsers));
    });

    // Lấy Public Key người nhận
    socket.on('get_public_key', (targetUser, callback) => {
        const user = registeredUsers[targetUser];
        if (user && onlineUsers[targetUser]) {
            callback({
                success: true,
                publicKey: user.publicKey,
                signPublicKey: user.signPublicKey
            });
        } else {
            callback({ success: false, message: 'Người dùng không trực tuyến!' });
        }
    });

    // Gửi tin nhắn mã hóa
    socket.on('send_secure_message', (packet) => {
        const receiverSocketId = onlineUsers[packet.receiverUsername];
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('receive_secure_message', packet);
        }
    });

    // Ngắt kết nối
    socket.on('disconnect', () => {
        if (socket.username && onlineUsers[socket.username]) {
            delete onlineUsers[socket.username];
            io.emit('update_user_list', Object.keys(onlineUsers));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
