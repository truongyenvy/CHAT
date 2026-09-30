const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public'));

// Danh sách lưu trữ người dùng online & khóa công khai
const users = {}; // Cấu trúc: { username: { socketId, publicKey, signPublicKey } }

io.on('connection', (socket) => {
    console.log('Người dùng kết nối:', socket.id);

    // 1. Nhận thông tin đăng ký từ Client (gồm cả khóa Mã hóa & khóa Chữ ký)
    socket.on('register_user', (data) => {
        const { username, publicKey, signPublicKey } = data;
        
        users[username] = {
            socketId: socket.id,
            publicKey: publicKey,
            signPublicKey: signPublicKey
        };
        socket.username = username;

        console.log(`Đã đăng ký: ${username}`);

        // Gửi danh sách tất cả các Username cho TẤT CẢ mọi người
        io.emit('update_user_list', Object.keys(users));
    });

    // 2. Trả về Public Key khi có yêu cầu gửi tin nhắn
    socket.on('get_public_key', (targetUser, callback) => {
        if (users[targetUser]) {
            callback({
                success: true,
                publicKey: users[targetUser].publicKey,
                signPublicKey: users[targetUser].signPublicKey
            });
        } else {
            callback({ success: false, message: 'Người dùng không tồn tại hoặc đã ngắt kết nối!' });
        }
    });

    // 3. Chuyển tiếp tin nhắn đã mã hóa đến đúng người nhận
    socket.on('send_secure_message', (packet) => {
        const receiver = users[packet.receiverUsername];
        if (receiver) {
            io.to(receiver.socketId).emit('receive_secure_message', packet);
        }
    });

    // 4. Xử lý khi người dùng ngắt kết nối
    socket.on('disconnect', () => {
        if (socket.username && users[socket.username]) {
            delete users[socket.username];
            // Cập nhật lại danh sách online cho những người còn lại
            io.emit('update_user_list', Object.keys(users));
            console.log(`Đã thoát: ${socket.username}`);
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
