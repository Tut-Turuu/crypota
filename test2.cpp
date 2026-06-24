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

using namespace boost;
using boost::asio::ip::tcp;

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
        std::string buffer;
        std::array<char, 1024> chunk;
        
        while (true) {
            size_t length = co_await socket_.async_read_some(
                asio::buffer(chunk),
                asio::use_awaitable
            );
            
            buffer.append(chunk.data(), length);
            
            try {
                co_return Packet::from_raw(buffer);
            } catch (const std::invalid_argument&) {
                // Недостаточно данных, читаем еще
                continue;
            }
        }
    }
    
    // Обработка пакета
    asio::awaitable<void> handle_packet(std::unique_ptr<Packet> packet) {
        switch (packet->type()) {
            case packet_type::registration_req:
                co_await handle_registration(
                    std::move(static_cast<RegistrationRequest&>(*packet))
                );
                break;
                
            case packet_type::message_req:
                co_await handle_message(
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
    
    asio::awaitable<void> handle_registration(RegistrationRequest req) {
        std::cout << "Registration request with public key" << std::endl;
        
        // Создаем ID пользователя
        uint32_t user_id = ++next_user_id;
        users_[user_id] = req.public_key;  // сохраняем ключ
        
        // Отправляем ответ
        RegistrationResponse response(user_id);
        co_await send_packet(response);
    }
    
    asio::awaitable<void> handle_message(MessageRequest req) {
        std::cout << "Message from " << req.destination_id 
                  << ": " << req.message << std::endl;
        
        // Пересылаем сообщение (тут можно добавить логику)
        // ...
        
        MessageResponse response(0);
        co_await send_packet(response);
    }
    
    asio::awaitable<void> handle_get_public_key(GetOtherPubRequest req) {
        std::cout << "Get public key for user: " << req.target_user_id << std::endl;
        
        auto it = users_.find(req.target_user_id);
        if (it != users_.end()) {
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
    static uint32_t next_user_id;
    static std::unordered_map<uint32_t, rsa::key_t> users_;
};

// Статические поля
uint32_t Session::next_user_id = 0;
std::unordered_map<uint32_t, rsa::key_t> Session::users_;

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