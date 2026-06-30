#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <iomanip>
#include <memory>
#include <boost/asio/experimental/channel.hpp>
#include "storage.hpp"
#include "random.hpp"
#include "server_info.hpp"
#include "mpz_string.hpp"
#include "rsa.hpp"
#include "aes.hpp"
#include "packets.hpp"
#include "signature.hpp"

using namespace boost;
using asio::ip::tcp;
using boost::system::error_code;
using bool_channel = asio::experimental::channel<void(error_code, bool)>;


void print_hex(const std::string& str) {
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char c : str) {
        std::cout << std::setw(2) << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
}


auto get_server_endpoints(asio::io_context& io_ctxt) {
    tcp::resolver resolver(io_ctxt);
    return resolver.resolve(get_server_addr(), std::to_string(get_server_port()));
}

class Secure_Session: public std::enable_shared_from_this<Secure_Session> {
private:
    int my_id;
    rsa::key_t my_pub;
    rsa::key_t my_priv;
    rsa::key_t server_pub;
    std::string cr;
    std::string tmp_session_secret;
    aes::key_t tmp_sym;
    std::string session_secret = "";
    asio::io_context& io_context;
    tcp::socket socket;
    std::unordered_map<uint32_t, std::shared_ptr<bool_channel>> pub_channels;
    std::unordered_map<uint32_t, rsa::key_t> pub_by_id;
    std::unordered_map<uint32_t, std::shared_ptr<bool_channel>> sym_channels;
    std::unordered_map<uint32_t, aes::key_t> sym_by_id;

public:
    Secure_Session(asio::io_context& io_ctxt): io_context(io_ctxt), socket(io_context) {
        asio::connect(socket, get_server_endpoints(io_context));

    }

    void start() {

        asio::co_spawn(
            socket.get_executor(),
            [self = shared_from_this()]() -> asio::awaitable<void> {
                co_await self->run();
            },
            asio::detached
        );
    }

    void send_message(uint32_t dest_id, const std::string& message) {
        asio::co_spawn(
            socket.get_executor(),
            [self = shared_from_this(), dest_id, message]() -> asio::awaitable<void> {
                co_await self->init_send_message(dest_id, message);
            },
            asio::detached
        );
    }

private:

    void generate_keys() {
        rsa::RSA alg;
        my_priv = alg.share_my_private_key();
        my_pub = alg.share_my_public_key();
        store_my_pub(my_pub);
        store_my_priv(my_priv);
    }

    asio::awaitable<void> run() {
        try {
            get_server_pub(server_pub);
            if (!get_my_pub_from_fs(my_pub) || !get_my_priv_from_fs(my_priv)) {
                generate_keys();
            }

            if (!get_my_id_from_fs(my_id)) {
                co_await registration();
            }

            co_await handshake();


            std::cout << "reading packets" << std::endl;
            while (true) {
                auto packet = co_await read_packet();
                co_await handle_packet(std::move(packet));
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                std::cout << "Server disconected" << std::endl;
            } else {
                std::cerr << "System error: " << e.what() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Session error: " << e.what() << std::endl;
        }
        co_return;
    }

    asio::awaitable<void> handle_packet(std::unique_ptr<Packet> packet) {
        switch (packet->type()) {

            case packet_type::message_req:
                co_await handle_get_message(
                    std::move(static_cast<MessageRequest&>(*packet))
                );
                break;
            case packet_type::message_res:
                co_await handle_get_message(
                    std::move(static_cast<MessageResponse&>(*packet))
                );
                break;
            case packet_type::get_other_pub_res:
                co_await handle_get_public_key(
                    std::move(static_cast<GetOtherPubResponse&>(*packet))
                );
                break;
            case packet_type::send_sym_req:
                co_await handle_send_sym(
                    std::move(static_cast<SendSymRequest&>(*packet))
                );
                break;
            case packet_type::send_sym_res:
                co_await handle_send_sym(
                    std::move(static_cast<SendSymResponse&>(*packet))
                );
                break;
                
            default:
                std::cerr << "Unknown packet type: " 
                          << static_cast<uint32_t>(packet->type()) << std::endl;
        }
        co_return;
    }


    asio::awaitable<void> send_packet(const Packet& packet) {
        if (session_secret == "") {
            std::string data = packet.serialize();
            co_await asio::async_write(
                socket,
                asio::buffer(data),
                asio::use_awaitable
            );
        } else {
            std::string data = hmac_packet(packet.serialize(), session_secret);
            co_await asio::async_write(
                socket,
                asio::buffer(data),
                asio::use_awaitable
            );
        }
        co_return;
    }

    // Чтение пакета
    asio::awaitable<std::unique_ptr<Packet>> read_packet() {
        uint32_t len_limit = 2048;
        uint32_t len;
        std::string str_len;
        str_len.resize(4);
        system::error_code ec;
        size_t length = co_await socket.async_read_some(asio::buffer(str_len), asio::use_awaitable);
        if (length < 4) {

        }
        len = packet_utils::string_to_number(str_len);
        if (len >= len_limit) {

        }
        std::string payload;
        payload.resize(len);

        length = co_await socket.async_read_some(asio::buffer(payload), asio::use_awaitable);

        if (session_secret == "") {

            std::unique_ptr<Packet> packet = Packet::from_payload(payload);
            co_return packet;
        } else {
            auto hmaced_packet = str_len + payload;
            if (verify_hmac(hmaced_packet, session_secret)) {
                std::unique_ptr<Packet> packet = Packet::from_payload(get_raw_packet(hmaced_packet).substr(4));
                co_return packet;
            } else {
                throw std::runtime_error("HMAC verification failed");
            } 
        }

    }

    // registration

    asio::awaitable<void> registration() {
        std::cout << "registration init " << std::endl;
        std::unique_ptr<Packet> req = std::make_unique<RegistrationRequest>(my_pub);
        co_await send_packet(*req);


        auto res = co_await read_packet();

        auto reg_res = dynamic_cast<RegistrationResponse*>(res.get());
        if (reg_res == nullptr) {
            std::cout << "registration failed" << std::endl;
            co_return;
        }

        my_id = reg_res->user_id;

        std::cout << "my new id is: " << my_id << std::endl;
        co_return;
        // store_my_id(reg_res->user_id);
    }
    // handshake

    asio::awaitable<void> handshake() {
        std::cout << "handshake init" << std::endl;
        std::string cr = get_random_str(64);
        std::unique_ptr<Packet> req = std::make_unique<HandshakeRequest1>(cr, my_id);
        co_await send_packet(*req);

        auto res = co_await read_packet();

        auto hand1_res = dynamic_cast<HandshakeResponse1*>(res.get());
        if (hand1_res == nullptr) {
            std::cout << "handshake failed" << std::endl;
            co_return;
        }
        if (!hand1_res->is_success()) {
            std::cout << "handshake failed" << std::endl;
            co_return;
        }

        Verifier verif(server_pub);
        if (!verif.verify(hand1_res->signature, cr)) {
            std::cout << "invalid server signature" << std::endl;
            co_return;
        }

        Signer sign(my_priv);
        auto signature = sign.sign(hand1_res->server_random);
        auto tmp_session_secret = get_random_str(4);

        auto encrypted_session_secret = mpz_to_string(rsa::encrypt_message(string_to_mpz(tmp_session_secret), server_pub));
        req = std::make_unique<HandshakeRequest2>(signature, encrypted_session_secret);
        co_await send_packet(*req);

        res = co_await read_packet();

        auto hand2_res = dynamic_cast<HandshakeResponse2*>(res.get());
        if (hand2_res == nullptr) {
            std::cout << "handshake failed wrong response" << std::endl;
            co_return;
        }

        if (!hand2_res->is_success()) {
            std::cout << "handshake unsuccess" << std::endl;
            co_return;
        }

        session_secret = tmp_session_secret;

        std::cout << "handshake passed" << std::endl;
        co_return;
    }


    // message
    asio::awaitable<void> init_send_message(uint32_t dest_id, const std::string& message) {
        std::cout << "send message init" << std::endl;
        aes::key_t sym;
        auto it = sym_by_id.find(dest_id);
        if (it == sym_by_id.end()) {
            sym_channels[dest_id] = std::make_shared<bool_channel>(io_context);
            co_await init_send_sym(dest_id);

            co_await sym_channels[dest_id]->async_receive(asio::use_awaitable);
            sym = sym_by_id[dest_id];
            sym_channels.erase(dest_id);
        } else {
            sym = sym_by_id[dest_id];
        }

    
        aes::Chipher chipher(sym);
        

        std::string encrypted_message = chipher.encrypt_string(message);

        print_hex(encrypted_message);
        std::unique_ptr<Packet> req = std::make_unique<MessageRequest>(dest_id, my_id, encrypted_message);

        co_await send_packet(*req);  
    }

    asio::awaitable<void> handle_get_message(MessageRequest req) {
        std::cout << "got a message" << std::endl;
        uint32_t source = req.source_id;
        aes::key_t sym = sym_by_id[source];

        aes::Chipher chipher(sym);

        
        print_hex(req.message);

        std::string message = chipher.decrypt_string(req.message);
        std::cout << message << std::endl;

        co_return;

    }

    asio::awaitable<void> handle_get_message(MessageResponse res) {
        co_return;
    }

    // get public key
    asio::awaitable<void> init_get_public_key(uint32_t dest_id) {
        std::cout << "get_other_pub init " << std::endl;
        std::unique_ptr<Packet> req = std::make_unique<GetOtherPubRequest>(dest_id);
        // std::cout << packet_utils::hex_rep(req->serialize()) << std::endl;

        co_await send_packet(*req);
        co_return;
    }

    asio::awaitable<void> handle_get_public_key(GetOtherPubResponse res) {
        if (!res.is_success()) {
            std::cout << "get_other_pub server not found, id:" << res.dest_id << std::endl;
            co_return;
        }
        std::cout << "got public key" << std::endl;
        if (pub_by_id.find(res.dest_id) == pub_by_id.end()) {
            pub_by_id[res.dest_id] = res.public_key;
        }

        auto it = pub_channels.find(res.dest_id);
        if (it != pub_channels.end()) {
            
            co_await (*it).second->async_send(error_code{}, true, asio::use_awaitable);
            std::cout << "sent pub to channel by id: " << res.dest_id << std::endl;
        }
        auto ids_pub = res.public_key;
        // store_pub_by_id(res.public_key, res.dest_id);

        co_return;
    }

    // send sym
    asio::awaitable<void> init_send_sym(uint32_t dest_id) {

        std::cout << "send_sym init " << std::endl;
    
        aes::key_gen(tmp_sym);


        rsa::key_t ids_pub;
        

        if (!get_pub_by_id_from_fs(ids_pub, dest_id)) {
            std::cout << "pub by id " << dest_id << " not found in fs" << std::endl;
            pub_channels[dest_id] = std::make_shared<bool_channel>(io_context);
            co_await init_get_public_key(dest_id);
            std::cout << "awaiting pub from channel by id: " << dest_id << std::endl;

            co_await pub_channels[dest_id]->async_receive(asio::use_awaitable);

            std::cout << "awaited pub from channel by id: " << dest_id << std::endl;
            ids_pub = pub_by_id[dest_id];
            pub_channels.erase(dest_id);
        }


        std::string chiphered_key = mpz_to_string(rsa::encrypt_message(string_to_mpz(aes::serialize_key_to_string(tmp_sym)), ids_pub));
        std::unique_ptr<Packet> req = std::make_unique<SendSymRequest>(dest_id, my_id, chiphered_key);
        // std::cout << "send_sym request: " << packet_utils::hex_rep(req->serialize()) << std::endl;
        co_await send_packet(*req);
        co_return;  

    } 
    asio::awaitable<void> handle_send_sym(SendSymRequest req) {
        auto res = SendSymResponse::success(req.source_id, req.dest_id);
        co_await send_packet(*res);
        co_return;
    }

    asio::awaitable<void> handle_send_sym(SendSymResponse res) {
        if (res.is_success()) {
            std::cout << "successful send sym response" << std::endl;

            sym_by_id[res.source_id] = tmp_sym;
            aes::store_key(std::to_string(res.dest_id) + "/sym.key", tmp_sym);

            auto it = sym_channels.find(res.dest_id);
            if (it != sym_channels.end()) {
                co_await (*it).second->async_send(error_code{}, true, asio::use_awaitable);
            }
            
            
        }
        co_return;
    }


    





};

int main() {
    try {
        asio::io_context io_context;

        auto session = std::make_shared<Secure_Session>(io_context);
        session->start();
        asio::co_spawn(
            io_context,
            [&session, &io_context]() -> asio::awaitable<void> {
                asio::steady_timer timer(io_context, std::chrono::seconds(2));
                co_await timer.async_wait(asio::use_awaitable);
                session->send_message(1, "message suka");
            },
            asio::detached
        );

        io_context.run();

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}