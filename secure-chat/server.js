const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public'));

// ==========================================
// SERVER DATA
// ==========================================

const registeredUsers = {};
const onlineUsers = {};

// ==========================================
// SHA-256
// ==========================================

function hashPassword(password) {
    return crypto
        .createHash('sha256')
        .update(password)
        .digest('hex');
}

// ==========================================
// SOCKET.IO
// ==========================================

io.on('connection', (socket) => {

    console.log('Client connected:', socket.id);

    // ==========================================
    // REGISTER
    // ==========================================

    socket.on('register_account', (data, callback) => {

        try {

            const {
                username,
                password,
                publicKey,
                signPublicKey
            } = data;

            if (
                !username ||
                !password ||
                !publicKey ||
                !signPublicKey
            ) {
                return callback({
                    success: false,
                    message: 'Vui lòng nhập đầy đủ thông tin!'
                });
            }

            if (username.length < 3) {
                return callback({
                    success: false,
                    message: 'Tên tài khoản phải có ít nhất 3 ký tự!'
                });
            }

            if (password.length < 4) {
                return callback({
                    success: false,
                    message: 'Mật khẩu phải có ít nhất 4 ký tự!'
                });
            }

            if (registeredUsers[username]) {
                return callback({
                    success: false,
                    message: 'Tên tài khoản đã tồn tại!'
                });
            }

            registeredUsers[username] = {
                passwordHash: hashPassword(password),
                publicKey: publicKey,
                signPublicKey: signPublicKey
            };

            console.log(`Registered: ${username}`);

            callback({
                success: true,
                message: 'Đăng ký thành công! Vui lòng đăng nhập.'
            });

        } catch (error) {

            console.error(error);

            callback({
                success: false,
                message: 'Có lỗi xảy ra khi đăng ký!'
            });
        }
    });

    // ==========================================
    // LOGIN
    // ==========================================

    socket.on('login_account', (data, callback) => {

        try {

            const {
                username,
                password,
                publicKey,
                signPublicKey
            } = data;

            const user = registeredUsers[username];

            if (!user) {

                return callback({
                    success: false,
                    message: 'Tài khoản không tồn tại!'
                });
            }

            if (
                user.passwordHash !==
                hashPassword(password)
            ) {

                return callback({
                    success: false,
                    message: 'Mật khẩu không đúng!'
                });
            }

            // Kiểm tra khóa
            if (
                user.publicKey !== publicKey ||
                user.signPublicKey !== signPublicKey
            ) {

                return callback({
                    success: false,
                    message:
                        'Khóa bảo mật không khớp. ' +
                        'Hãy đăng nhập trên trình duyệt đã đăng ký tài khoản.'
                });
            }

            // Nếu tài khoản đang đăng nhập ở nơi khác
            if (onlineUsers[username]) {

                const oldSocketId =
                    onlineUsers[username];

                const oldSocket =
                    io.sockets.sockets.get(
                        oldSocketId
                    );

                if (oldSocket) {

                    oldSocket.emit(
                        'force_logout',
                        {
                            message:
                                'Tài khoản của bạn vừa đăng nhập ở nơi khác.'
                        }
                    );

                    oldSocket.disconnect(true);
                }
            }

            onlineUsers[username] =
                socket.id;

            socket.username =
                username;

            console.log(`Login: ${username}`);

            callback({
                success: true,
                message: 'Đăng nhập thành công!'
            });

            io.emit(
                'update_user_list',
                Object.keys(onlineUsers)
            );

        } catch (error) {

            console.error(error);

            callback({
                success: false,
                message: 'Có lỗi xảy ra khi đăng nhập!'
            });
        }
    });

    // ==========================================
    // USER LIST
    // ==========================================

    socket.on('request_user_list', () => {

        socket.emit(
            'update_user_list',
            Object.keys(onlineUsers)
        );
    });

    // ==========================================
    // GET PUBLIC KEY
    // ==========================================

    socket.on(
        'get_public_key',
        (targetUser, callback) => {

            const user =
                registeredUsers[targetUser];

            if (!user) {

                return callback({
                    success: false,
                    message: 'Người dùng không tồn tại!'
                });
            }

            if (!onlineUsers[targetUser]) {

                return callback({
                    success: false,
                    message:
                        'Người dùng hiện không trực tuyến!'
                });
            }

            callback({
                success: true,
                publicKey: user.publicKey,
                signPublicKey: user.signPublicKey
            });
        }
    );

    // ==========================================
    // SEND PRIVATE MESSAGE
    // ==========================================

    socket.on(
        'send_secure_message',
        (packet) => {

            try {

                if (!socket.username) {
                    return;
                }

                // Không cho giả mạo sender
                if (
                    packet.senderUsername !==
                    socket.username
                ) {

                    console.warn(
                        'Fake sender detected!'
                    );

                    return;
                }

                const receiver =
                    packet.receiverUsername;

                const receiverSocketId =
                    onlineUsers[receiver];

                if (!receiverSocketId) {

                    socket.emit(
                        'message_send_error',
                        {
                            message:
                                'Người nhận hiện không trực tuyến!'
                        }
                    );

                    return;
                }

                const sender =
                    registeredUsers[
                        socket.username
                    ];

                if (!sender) {
                    return;
                }

                // ==========================================
                // SERVER TẠO PACKET RIÊNG CHO RECEIVER
                // ==========================================

                const securePacket = {

                    senderUsername:
                        socket.username,

                    receiverUsername:
                        receiver,

                    encryptedContent:
                        packet.encryptedContent,

                    encryptedAesKey:
                        packet.encryptedAesKey,

                    iv:
                        packet.iv,

                    signature:
                        packet.signature,

                    senderSignPubKey:
                        sender.signPublicKey,

                    timestamp:
                        packet.timestamp ||
                        Date.now()
                };

                // Chỉ gửi cho receiver
                io.to(receiverSocketId).emit(
                    'receive_secure_message',
                    securePacket
                );

            } catch (error) {

                console.error(
                    'Send message error:',
                    error
                );
            }
        }
    );

    // ==========================================
    // LOGOUT
    // ==========================================

    socket.on(
        'logout_account',
        () => {

            if (
                socket.username &&
                onlineUsers[
                    socket.username
                ] === socket.id
            ) {

                delete onlineUsers[
                    socket.username
                ];

                io.emit(
                    'update_user_list',
                    Object.keys(onlineUsers)
                );

                socket.username = null;
            }
        }
    );

    // ==========================================
    // DISCONNECT
    // ==========================================

    socket.on(
        'disconnect',
        () => {

            console.log(
                'Disconnected:',
                socket.id
            );

            if (
                socket.username &&
                onlineUsers[
                    socket.username
                ] === socket.id
            ) {

                delete onlineUsers[
                    socket.username
                ];

                io.emit(
                    'update_user_list',
                    Object.keys(onlineUsers)
                );
            }
        }
    );

});


// ==========================================
// START
// ==========================================

const PORT =
    process.env.PORT || 3000;

server.listen(
    PORT,
    () => {

        console.log(
            `Server running at http://localhost:${PORT}`
        );

    }
);
