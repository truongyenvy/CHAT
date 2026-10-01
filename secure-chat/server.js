const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public'));

// ======================================================
// DỮ LIỆU NGƯỜI DÙNG
// ======================================================

// {
//     username: {
//         passwordHash,
//         publicKey,
//         signPublicKey
//     }
// }

const registeredUsers = {};

// {
//     username: socketId
// }

const onlineUsers = {};


// ======================================================
// HÀM BĂM MẬT KHẨU
// ======================================================

function hashPassword(password) {
    return crypto
        .createHash('sha256')
        .update(password)
        .digest('hex');
}


// ======================================================
// SOCKET.IO
// ======================================================

io.on('connection', (socket) => {

    console.log('Client connected:', socket.id);


    // ==================================================
    // ĐĂNG KÝ
    // ==================================================

    socket.on('register_account', (data, callback) => {

        const {
            username,
            password,
            publicKey,
            signPublicKey
        } = data;

        // Kiểm tra dữ liệu
        if (!username || !password || !publicKey || !signPublicKey) {
            return callback({
                success: false,
                message: 'Vui lòng nhập đầy đủ thông tin!'
            });
        }

        // Kiểm tra tài khoản tồn tại
        if (registeredUsers[username]) {
            return callback({
                success: false,
                message: 'Tên tài khoản đã tồn tại!'
            });
        }

        // Tạo tài khoản
        registeredUsers[username] = {
            passwordHash: hashPassword(password),

            // Public key mã hóa RSA-OAEP
            publicKey: publicKey,

            // Public key chữ ký RSA-PSS
            signPublicKey: signPublicKey
        };

        console.log('Registered user:', username);

        callback({
            success: true,
            message: 'Đăng ký thành công! Vui lòng chuyển sang Đăng nhập.'
        });
    });


    // ==================================================
    // ĐĂNG NHẬP
    // ==================================================

    socket.on('login_account', (data, callback) => {

        const {
            username,
            password,
            publicKey,
            signPublicKey
        } = data;

        const user = registeredUsers[username];

        // Kiểm tra tài khoản
        if (!user) {
            return callback({
                success: false,
                message: 'Tài khoản hoặc mật khẩu không đúng!'
            });
        }

        // Kiểm tra mật khẩu
        if (user.passwordHash !== hashPassword(password)) {
            return callback({
                success: false,
                message: 'Tài khoản hoặc mật khẩu không đúng!'
            });
        }


        // ==================================================
        // KIỂM TRA PUBLIC KEY
        // ==================================================

        // Không cho client tự ý thay đổi key của tài khoản
        if (
            user.publicKey !== publicKey ||
            user.signPublicKey !== signPublicKey
        ) {
            return callback({
                success: false,
                message:
                    'Khóa bảo mật không khớp với tài khoản này. Hãy đăng nhập trên thiết bị đã đăng ký.'
            });
        }


        // ==================================================
        // LƯU PHIÊN ĐĂNG NHẬP
        // ==================================================

        // Nếu tài khoản đang đăng nhập ở socket khác
        if (onlineUsers[username]) {

            const oldSocketId = onlineUsers[username];

            // Ngắt phiên cũ
            const oldSocket = io.sockets.sockets.get(oldSocketId);

            if (oldSocket) {
                oldSocket.emit('force_logout', {
                    message: 'Tài khoản đã đăng nhập ở nơi khác.'
                });

                oldSocket.disconnect(true);
            }
        }


        // Lưu socket
        onlineUsers[username] = socket.id;

        // Gắn username vào socket
        socket.username = username;


        console.log('User logged in:', username);


        callback({
            success: true,
            message: 'Đăng nhập thành công!'
        });


        // Cập nhật danh sách online
        io.emit(
            'update_user_list',
            Object.keys(onlineUsers)
        );
    });


    // ==================================================
    // YÊU CẦU DANH SÁCH USER ONLINE
    // ==================================================

    socket.on('request_user_list', () => {

        socket.emit(
            'update_user_list',
            Object.keys(onlineUsers)
        );
    });


    // ==================================================
    // LẤY PUBLIC KEY CỦA USER
    // ==================================================

    socket.on('get_public_key', (targetUser, callback) => {

        const user = registeredUsers[targetUser];

        if (!user) {
            return callback({
                success: false,
                message: 'Không tìm thấy người dùng!'
            });
        }

        if (!onlineUsers[targetUser]) {
            return callback({
                success: false,
                message: 'Người dùng không trực tuyến!'
            });
        }


        callback({
            success: true,

            // Public key RSA-OAEP
            publicKey: user.publicKey,

            // Public key RSA-PSS
            signPublicKey: user.signPublicKey
        });
    });


    // ==================================================
    // GỬI TIN NHẮN MÃ HÓA
    // ==================================================

    socket.on('send_secure_message', (packet) => {

        // ------------------------------------------------
        // 1. Kiểm tra socket đã đăng nhập chưa
        // ------------------------------------------------

        if (!socket.username) {
            return;
        }


        // ------------------------------------------------
        // 2. KIỂM TRA NGƯỜI GỬI
        // ------------------------------------------------

        // Không tin username do client tự gửi
        if (packet.senderUsername !== socket.username) {

            console.log(
                'Blocked fake sender:',
                packet.senderUsername,
                'actual:',
                socket.username
            );

            return;
        }


        // ------------------------------------------------
        // 3. Kiểm tra receiver
        // ------------------------------------------------

        const receiverUsername = packet.receiverUsername;

        if (!receiverUsername) {
            return;
        }


        // ------------------------------------------------
        // 4. Lấy socket người nhận
        // ------------------------------------------------

        const receiverSocketId =
            onlineUsers[receiverUsername];

        if (!receiverSocketId) {
            return;
        }


        // ------------------------------------------------
        // 5. LẤY SIGNING PUBLIC KEY TỪ SERVER
        // ------------------------------------------------

        const senderUser =
            registeredUsers[socket.username];

        if (!senderUser) {
            return;
        }


        // Không tin senderSignPubKey do client gửi
        // Server tự lấy key đã đăng ký
        const securePacket = {

            senderUsername:
                socket.username,

            receiverUsername:
                receiverUsername,

            encryptedContent:
                packet.encryptedContent,

            encryptedAesKey:
                packet.encryptedAesKey,

            iv:
                packet.iv,

            signature:
                packet.signature,

            // Server tự gắn key đã đăng ký
            senderSignPubKey:
                senderUser.signPublicKey,

            // Thời gian gửi
            timestamp:
                packet.timestamp || Date.now()
        };


        // ------------------------------------------------
        // 6. Chuyển ciphertext cho người nhận
        // ------------------------------------------------

        io.to(receiverSocketId).emit(
            'receive_secure_message',
            securePacket
        );
    });


    // ==================================================
    // ĐĂNG XUẤT
    // ==================================================

    socket.on('logout_account', () => {

        if (
            socket.username &&
            onlineUsers[socket.username] === socket.id
        ) {

            delete onlineUsers[socket.username];

            io.emit(
                'update_user_list',
                Object.keys(onlineUsers)
            );

            console.log(
                'User logged out:',
                socket.username
            );

            socket.username = null;
        }
    });


    // ==================================================
    // NGẮT KẾT NỐI
    // ==================================================

    socket.on('disconnect', () => {

        if (
            socket.username &&
            onlineUsers[socket.username] === socket.id
        ) {

            delete onlineUsers[socket.username];

            io.emit(
                'update_user_list',
                Object.keys(onlineUsers)
            );

            console.log(
                'User disconnected:',
                socket.username
            );
        }
    });

});


// ======================================================
// CHẠY SERVER
// ======================================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {

    console.log(
        `Server running at http://localhost:${PORT}`
    );

});
