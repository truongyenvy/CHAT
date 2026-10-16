const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    maxHttpBufferSize: 50 * 1024 * 1024 // Hỗ trợ gửi file/ảnh đến 50MB
});

app.use(express.static('public'));

// CSDL Lưu trữ thông tin tài khoản và tin nhắn
const registeredUsers = {}; // { username: { passwordHash, publicKey } }
const messageStore = [];    // Danh sách lưu toàn bộ tin nhắn mã hóa
const onlineUsers = {};     // Danh sách user đang online { username: socketId }

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function getChatKey(user1, user2) {
    return [user1, user2].sort().join('::');
}

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // ==========================================
    // ĐĂNG KÝ
    // ==========================================
    socket.on('register_account', (data, callback) => {
        try {
            const { username, password, publicKey } = data;

            if (!username || !password || !publicKey) {
                return callback({ success: false, message: 'Vui lòng nhập đầy đủ thông tin!' });
            }
            if (username.length < 3) {
                return callback({ success: false, message: 'Tên tài khoản phải từ 3 ký tự!' });
            }
            if (password.length < 4) {
                return callback({ success: false, message: 'Mật khẩu phải từ 4 ký tự!' });
            }
            if (registeredUsers[username]) {
                return callback({ success: false, message: 'Tên tài khoản đã tồn tại!' });
            }

            // Lưu tài khoản & khóa
            registeredUsers[username] = {
                passwordHash: hashPassword(password),
                publicKey: publicKey
            };

            console.log(`Registered successfully: ${username}`);
            callback({ 
                success: true, 
                message: 'Đăng ký thành công! Đang chuyển sang màn hình đăng nhập...' 
            });
        } catch (error) {
            console.error(error);
            callback({ success: false, message: 'Có lỗi xảy ra khi đăng ký!' });
        }
    });

    // ==========================================
    // ĐĂNG NHẬP & TẢI LẠI LỊCH SỬ TIN NHẮN
    // ==========================================
    socket.on('login_account', (data, callback) => {
        try {
            const { username, password, publicKey } = data;
            const user = registeredUsers[username];

            if (!user) {
                return callback({ success: false, message: 'Tài khoản không tồn tại!' });
            }
            if (user.passwordHash !== hashPassword(password)) {
                return callback({ success: false, message: 'Mật khẩu không đúng!' });
            }

            // Cập nhật Public Key phiên mới
            user.publicKey = publicKey;

            // Xử lý nếu tài khoản đang online ở tab/thiết bị khác
            if (onlineUsers[username]) {
                const oldSocketId = onlineUsers[username];
                const oldSocket = io.sockets.sockets.get(oldSocketId);
                if (oldSocket) {
                    oldSocket.emit('force_logout', { message: 'Tài khoản của bạn vừa đăng nhập ở nơi khác.' });
                    oldSocket.disconnect(true);
                }
            }

            onlineUsers[username] = socket.id;
            socket.username = username;

            console.log(`Login successful: ${username}`);

            // Lấy toàn bộ lịch sử tin nhắn liên quan tới user này
            const userHistory = messageStore.filter(
                m => m.senderUsername === username || m.receiverUsername === username
            );

            callback({
                success: true,
                message: 'Đăng nhập thành công!',
                history: userHistory
            });

            io.emit('update_user_list', Object.keys(onlineUsers));
        } catch (error) {
            console.error(error);
            callback({ success: false, message: 'Có lỗi xảy ra khi đăng nhập!' });
        }
    });

    socket.on('request_user_list', () => {
        socket.emit('update_user_list', Object.keys(onlineUsers));
    });

    // ==========================================
    // TRẠNG THÁI ĐANG GÕ (TYPING)
    // ==========================================
    socket.on('typing', (data) => {
        if (!socket.username) return;
        const receiverSocketId = onlineUsers[data.receiverUsername];
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('user_typing', {
                senderUsername: socket.username,
                isTyping: data.isTyping
            });
        }
    });

    // ==========================================
    // LẤY PUBLIC KEY
    // ==========================================
    socket.on('get_public_key', (targetUser, callback) => {
        const user = registeredUsers[targetUser];
        if (!user) {
            return callback({ success: false, message: 'Người dùng không tồn tại!' });
        }
        if (!onlineUsers[targetUser]) {
            return callback({ success: false, message: 'Người dùng hiện không trực tuyến!' });
        }
        callback({
            success: true,
            publicKey: user.publicKey
        });
    });

    // ==========================================
    // GỬI & LƯU TIN NHẮN
    // ==========================================
    socket.on('send_secure_message', (packet) => {
        try {
            if (!socket.username || packet.senderUsername !== socket.username) return;

            const receiver = packet.receiverUsername;
            const receiverSocketId = onlineUsers[receiver];

            const securePacket = {
                msgId: packet.msgId || ('msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5)),
                senderUsername: socket.username,
                receiverUsername: receiver,
                encryptedContent: packet.encryptedContent,
                encryptedAesKey: packet.encryptedAesKey,
                iv: packet.iv,
                timestamp: packet.timestamp || Date.now(),
                hash: packet.hash,
                ttl: packet.ttl || 0
            };

            // 1. Lưu vào CSDL Server để khôi phục khi đăng nhập lại
            messageStore.push(securePacket);

            // 2. Gửi realtime cho người nhận nếu đang online
            if (receiverSocketId) {
                io.to(receiverSocketId).emit('receive_secure_message', securePacket);
                socket.emit('message_status_update', { msgId: securePacket.msgId, status: 'received' });
            }
        } catch (error) {
            console.error('Send message error:', error);
        }
    });

    // ==========================================
    // ĐÃ ĐỌC TIN NHẮN
    // ==========================================
    socket.on('mark_as_read', (data) => {
        if (!socket.username) return;
        const senderSocketId = onlineUsers[data.senderUsername];
        if (senderSocketId) {
            io.to(senderSocketId).emit('message_status_update', { msgId: data.msgId, status: 'read' });
        }
    });

    // ==========================================
    // ĐĂNG XUẤT
    // ==========================================
    socket.on('logout_account', () => {
        if (socket.username && onlineUsers[socket.username] === socket.id) {
            delete onlineUsers[socket.username];
            io.emit('update_user_list', Object.keys(onlineUsers));
            socket.username = null;
        }
    });

    socket.on('disconnect', () => {
        if (socket.username && onlineUsers[socket.username] === socket.id) {
            delete onlineUsers[socket.username];
            io.emit('update_user_list', Object.keys(onlineUsers));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
