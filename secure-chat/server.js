const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// Hỗ trợ truyền File/Ảnh mã hóa lên đến 50MB
const io = new Server(server, {
    maxHttpBufferSize: 50 * 1024 * 1024
});

app.use(express.static('public'));

const registeredUsers = {};
const onlineUsers = {};

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // ==========================================
    // ĐĂNG KÝ
    // ==========================================
    socket.on('register_account', (data, callback) => {
        try {
            const { username, password, publicKey, signPublicKey } = data;

            if (!username || !password || !publicKey) {
                return callback({ success: false, message: 'Vui lòng nhập đầy đủ thông tin!' });
            }
            if (username.length < 3) {
                return callback({ success: false, message: 'Tên tài khoản phải có ít nhất 3 ký tự!' });
            }
            if (password.length < 4) {
                return callback({ success: false, message: 'Mật khẩu phải có ít nhất 4 ký tự!' });
            }
            if (registeredUsers[username]) {
                return callback({ success: false, message: 'Tên tài khoản đã tồn tại!' });
            }

            registeredUsers[username] = {
                passwordHash: hashPassword(password),
                publicKey: publicKey,
                signPublicKey: signPublicKey || publicKey
            };

            console.log(`Registered: ${username}`);
            callback({ success: true, message: 'Đăng ký thành công! Vui lòng đăng nhập.' });
        } catch (error) {
            console.error(error);
            callback({ success: false, message: 'Có lỗi xảy ra khi đăng ký!' });
        }
    });

    // ==========================================
    // ĐĂNG NHẬP
    // ==========================================
    socket.on('login_account', (data, callback) => {
        try {
            const { username, password, publicKey, signPublicKey } = data;
            const user = registeredUsers[username];

            if (!user) {
                return callback({ success: false, message: 'Tài khoản không tồn tại!' });
            }
            if (user.passwordHash !== hashPassword(password)) {
                return callback({ success: false, message: 'Mật khẩu không đúng!' });
            }

            // Luôn cập nhật Public Key mới nhất của phiên này
            user.publicKey = publicKey;
            user.signPublicKey = signPublicKey || publicKey;

            // Xử lý nếu tài khoản đang đăng nhập ở nơi khác
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

            console.log(`Login: ${username}`);
            callback({ success: true, message: 'Đăng nhập thành công!' });
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
            publicKey: user.publicKey,
            signPublicKey: user.signPublicKey
        });
    });

    // ==========================================
    // GỬI TIN NHẮN
    // ==========================================
    socket.on('send_secure_message', (packet) => {
        try {
            if (!socket.username || packet.senderUsername !== socket.username) return;

            const receiver = packet.receiverUsername;
            const receiverSocketId = onlineUsers[receiver];

            if (!receiverSocketId) {
                return socket.emit('message_send_error', { message: 'Người nhận hiện không trực tuyến!' });
            }

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

            io.to(receiverSocketId).emit('receive_secure_message', securePacket);
            socket.emit('message_status_update', { msgId: securePacket.msgId, status: 'received' });
        } catch (error) {
            console.error('Send message error:', error);
        }
    });

    // ==========================================
    // XÁC NHẬN ĐÃ ĐỌC TIN NHẮN
    // ==========================================
    socket.on('mark_as_read', (data) => {
        if (!socket.username) return;
        const senderSocketId = onlineUsers[data.senderUsername];
        if (senderSocketId) {
            io.to(senderSocketId).emit('message_status_update', { msgId: data.msgId, status: 'read' });
        }
    });

    // ==========================================
    // DĂNG XUẤT / NGẮT KẾT NỐI
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
