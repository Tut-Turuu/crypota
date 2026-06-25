#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <iostream>
#include <memory>
#include <string>
#include "rsa.hpp"
#include "aes.hpp"
#include "packets.hpp"
#include "signature.hpp"
#include "random.hpp"
#include "storage.hpp"
#include "mpz_string.hpp"

using namespace boost;
using boost::asio::ip::tcp;


rsa::key_t server_pub;
rsa::key_t server_priv;


// ==================== КЛАСС СЕССИИ ====================
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) 
        : socket_(std::move(socket)) {}
    
    // Запуск сессии
    void start() {
        asio::co_spawn(
            socket_.get_executor(),
            [self = shared_from_this()]() -> asio::awaitable<void> {
                co_await self->run();
            },
            asio::detached
        );
    }
    
private:

    // Главный цикл сессии
    asio::awaitable<void> run() {
        try {

            while (true) {
                auto packet = co_await read_packet();
                co_await handle_packet(std::move(packet));
            }
        } catch (const std::exception& e) {
            std::cerr << "Session error: " << e.what() << std::endl;
        }
    }
    
    // Чтение пакета
    asio::awaitable<std::unique_ptr<Packet>> read_packet() {
        uint32_t len_limit = 2048;
        uint32_t len;
        std::string str_len;
        str_len.resize(4);
        system::error_code ec;
        size_t length = co_await socket_.async_read_some(asio::buffer(str_len), asio::use_awaitable);
        if (length < 4) {

        }
        len = packet_utils::string_to_number(str_len);
        if (len >= len_limit) {

        }
        std::string payload;
        payload.resize(len);

        length = co_await socket_.async_read_some(asio::buffer(payload), asio::use_awaitable);

        std::unique_ptr<Packet> packet = Packet::from_payload(payload);
        co_return packet;

    }

    asio::awaitable<void> flush_queue() {
        
    }
    
    // Обработка пакета
    asio::awaitable<void> handle_packet(std::unique_ptr<Packet> packet) {
        switch (packet->type()) {
            case packet_type::handshake_req1:
                co_await handle_handshake1(
                    std::move(static_cast<HandshakeRequest1&>(*packet))
                );
                break;
            case packet_type::handshake_req2:
                co_await handle_handshake2(
                    std::move(static_cast<HandshakeRequest2&>(*packet))
                );
                break;
            case packet_type::registration_req:
                co_await handle_registration(
                    std::move(static_cast<RegistrationRequest&>(*packet))
                );
                break;
                
            case packet_type::message_req:
                co_await handle_resend_message(
                    std::move(static_cast<MessageRequest&>(*packet))
                );
                break;
                
            case packet_type::get_other_pub_req:
                co_await handle_get_public_key(
                    std::move(static_cast<GetOtherPubRequest&>(*packet))
                );
                break;
                
            default:
                std::cerr << "Unknown packet type: " 
                          << static_cast<uint32_t>(packet->type()) << std::endl;
        }
    }
    
    // ============ ОБРАБОТЧИКИ КОНКРЕТНЫХ ПАКЕТОВ ============

    asio::awaitable<bool> handle_handshake1(HandshakeRequest1 req) {

        auto hand1_req = dynamic_cast<HandshakeRequest1*>(&req);
        if (hand1_req == nullptr) {
            std::cout << "handshake failed" << std::endl;
            co_return true;
        }
        auto it = pub_by_id.find(hand1_req->user_id);
        if (it != pub_by_id.end()) {
            user_pub = it->second;
        } else {
            std::cout << "cant find pub by id: " << hand1_req->user_id << std::endl;
            co_return false;
        }

        Signer sign(server_priv);
        auto signature = sign.sign(hand1_req->client_random);
        sr = get_random_str(64);

        auto res = HandshakeResponse1::success(sr, signature);
        co_await send_packet(*res);

        co_return true;
    }

    asio::awaitable<bool> handle_handshake2(HandshakeRequest2 req) {

        auto hand2_req = dynamic_cast<HandshakeRequest2*>(&req);
        if (hand2_req == nullptr) {
            std::cout << "handshake failed" << std::endl;
            co_return true;
        }

        Verifier verif(user_pub);
        if (!verif.verify(hand2_req->signature, sr)) {
            std::cout << "Invalid client signature" << std::endl;
            co_return false;
        }

        session_secret = mpz_to_string(rsa::decrypt_message(string_to_mpz(hand2_req->encrypted_session_id), server_priv));

        auto res = HandshakeResponse2::success();

        co_await send_packet(*res);

        co_return true;
    }

    
    asio::awaitable<void> handle_registration(RegistrationRequest req) {
        std::cout << "Registration request with public key" << std::endl;
        uint32_t user_id;
        auto it = id_by_pub.find(req.public_key);
        if (it != id_by_pub.end()) {
            user_id = it->second;
        } else {
            user_id = ++next_user_id;
            pub_by_id[user_id] = req.public_key;  // сохраняем ключ
            id_by_pub[req.public_key] = user_id;
        }

        // Отправляем ответ
        RegistrationResponse response(user_id);
        co_await send_packet(response);
    }

    asio::awaitable<bool> handle_ping(PingRequest req) {
        PingResponse response;
        co_await send_packet(response);
    } 

    asio::awaitable<bool> handle_resend_sym(SendSymRequest req) {

        auto it = sessions.find(req.destination_id);
        if (it != sessions.end()) {
            auto session = sessions[req.destination_id];
            session->handle_send_sym(req);
        } else {
            queued_packets[req.destination_id].push_back(std::make_shared<SendSymRequest>(req));
        }
    }

    asio::awaitable<bool> handle_send_sym(SendSymRequest req) {
        co_await send_packet(req);

    }

    asio::awaitable<bool> handle_resend_sym(SendSymResponse res) {
        auto it = sessions.find(res.dest_id);
        if (it != sessions.end()) {
            auto session = sessions[res.dest_id];
            session->handle_send_sym(res);
        } else {
            queued_packets[res.dest_id].push_back(std::make_shared<SendSymResponse>(res));
        }
    }

    asio::awaitable<bool> handle_send_sym(SendSymResponse res) {
        co_await send_packet(res);

    }
    
    asio::awaitable<void> handle_resend_message(MessageRequest req) {
        auto it = sessions.find(req.destination_id);
        if (it != sessions.end()) {
            auto session = sessions[req.destination_id];
            session->handle_send_message(req);
        } else {
            queued_packets[req.destination_id].push_back(std::make_shared<MessageRequest>(req));
        }
    }

    asio::awaitable<void> handle_send_message(MessageRequest req) {
        co_await send_packet(req);
        
    }

    asio::awaitable<void> handle_resend_message(MessageResponse res) {
        auto it = sessions.find(res.dest_id);
        if (it != sessions.end()) {
            auto session = sessions[res.dest_id];
            session->handle_send_message(res);
        } else {
            queued_packets[res.dest_id].push_back(std::make_shared<MessageResponse>(res));
        }
    }

    asio::awaitable<void> handle_send_message(MessageResponse res) {
        co_await send_packet(res);
    }
    
    asio::awaitable<void> handle_get_public_key(GetOtherPubRequest req) {
        std::cout << "Get public key for user: " << req.target_user_id << std::endl;
        
        auto it = pub_by_id.find(req.target_user_id);
        if (it != pub_by_id.end()) {
            GetOtherPubResponse response(it->second);
            co_await send_packet(response);
        } else {
            // Пользователь не найден
            MessageResponse response(404);
            co_await send_packet(response);
        }
    }
    
    // ============ ОТПРАВКА ПАКЕТА ============
    
    asio::awaitable<void> send_packet(const Packet& packet) {
        std::string data = packet.serialize();
        co_await asio::async_write(
            socket_,
            asio::buffer(data),
            asio::use_awaitable
        );
    }
    
    // ============ ПОЛЯ ============
    
    tcp::socket socket_;
    std::string session_secret = "";
    rsa::key_t user_pub;
    uint32_t current_user;
    std::string sr;
    static uint32_t next_user_id;
    static std::unordered_map<uint32_t, rsa::key_t> pub_by_id;
    static std::unordered_map<rsa::key_t, uint32_t> id_by_pub;
    static std::unordered_map<uint32_t, std::shared_ptr<Session>> sessions;
    static std::unordered_map<uint32_t, std::vector<std::shared_ptr<Packet>>> queued_packets;
};

// Статические поля
uint32_t Session::next_user_id = 0;
std::unordered_map<uint32_t, rsa::key_t> Session::pub_by_id;
std::unordered_map<rsa::key_t, uint32_t> Session::id_by_pub;
std::unordered_map<uint32_t, std::shared_ptr<Session>> Session::sessions;
std::unordered_map<uint32_t, std::vector<std::shared_ptr<Packet>>> Session::queued_packets;

// ==================== СЕРВЕР ====================

class Server {
public:
    Server(asio::io_context& io, short port) 
        : io_(io), acceptor_(io, tcp::endpoint(tcp::v4(), port)) {}
    
    void start() {
        do_accept();
    }
    
private:
    void do_accept() {
        acceptor_.async_accept(
            [this](system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket))->start();
                }
                do_accept();
            }
        );
    }
    
    asio::io_context& io_;
    tcp::acceptor acceptor_;
};

// ==================== ТОЧКА ВХОДА ====================

int main(int argc, char* argv[]) {

    get_server_priv(server_priv);
    get_server_pub(server_pub);

    try {
        if (argc != 2) {
            std::cerr << "Usage: " << argv[0] << " <port>\n";
            return 1;
        }
        
        asio::io_context io(1);
        
        Server server(io, std::atoi(argv[1]));
        server.start();
        
        io.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}