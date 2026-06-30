#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <iomanip>
#include <memory>
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

class Secure_Session {
    int my_id;
    rsa::key_t my_pub;
    rsa::key_t my_priv;
    rsa::key_t server_pub;
    std::string session_secret = "";
    asio::io_context& io_context;
    tcp::socket socket;

    void connect() {
        asio::connect(socket, get_server_endpoints(io_context));
    }

    void send_request(const Packet& req) {
        if (session_secret == "") {
            asio::write(socket, asio::buffer(req.serialize()));
        } else {
            asio::write(socket, asio::buffer(hmac_packet(req.serialize(), session_secret)));
        }
    }

    std::unique_ptr<Packet> recv_response() {
        uint32_t len_limit = 2048;
        uint32_t len;
        std::string str_len;
        str_len.resize(4);
        system::error_code ec;
        size_t length = socket.read_some(asio::buffer(str_len), ec);
        if (length < 4) {

        }
        len = packet_utils::string_to_number(str_len);
        if (len >= len_limit) {

        }
        std::string payload;
        payload.resize(len);

        length = socket.read_some(asio::buffer(payload), ec);
        if (session_secret == "") {

            std::unique_ptr<Packet> packet = Packet::from_payload(payload);
            return packet;
        } else {
            auto hmaced_packet = str_len + payload;
            if (verify_hmac(hmaced_packet, session_secret)) {
                std::unique_ptr<Packet> packet = Packet::from_payload(get_raw_packet(hmaced_packet).substr(4));
                return packet;
            } else {
                throw std::runtime_error("HMAC verification failed");
            } 
        }
    }

    bool handshake() {
        std::string cr = get_random_str(64);
        std::unique_ptr<Packet> req = std::make_unique<HandshakeRequest1>(cr, my_id);
        send_request(*req);

        auto res = recv_response();

        auto hand1_res = dynamic_cast<HandshakeResponse1*>(res.get());
        if (hand1_res == nullptr) {
            std::cout << "handshake failed" << std::endl;
            return false;
        }
        if (!hand1_res->is_success()) {
            std::cout << "handshake failed" << std::endl;
            return false;
        }

        Verifier verif(server_pub);
        if (!verif.verify(hand1_res->signature, cr)) {
            std::cout << "invalid server signature" << std::endl;
        }

        Signer sign(my_priv);
        auto signature = sign.sign(hand1_res->server_random);
        auto tmp_session_secret = get_random_str(4);

        auto encrypted_session_secret = mpz_to_string(rsa::encrypt_message(string_to_mpz(tmp_session_secret), server_pub));
        req = std::make_unique<HandshakeRequest2>(signature, encrypted_session_secret);
        send_request(*req);

        res = recv_response();

        auto hand2_res = dynamic_cast<HandshakeResponse2*>(res.get());
        if (hand2_res == nullptr) {
            std::cout << "handshake failed wrong response" << std::endl;
            return false;
        }

        if (!hand2_res->is_success()) {
            std::cout << "handshake unsuccess" << std::endl;
            return false;
        }

        session_secret = tmp_session_secret;
        return true;
    }

    
public:
    Secure_Session(asio::io_context& io_ctxt): io_context(io_ctxt), socket(io_context) {
        get_server_pub(server_pub);
        connect();
        if (!get_my_pub_from_fs(my_pub) || !get_my_priv_from_fs(my_priv)) {
            generate_keys();
        }

        if (!get_my_id_from_fs(my_id)) {
            std::cout << "registration" << std::endl;
            registration();
        }

        handshake();

        std::cout << "handshake_passed" << std::endl;

        send_sym(606);
        send_message(060, "doat");
        
    }



    void generate_keys() {
        rsa::RSA alg;
        my_priv = alg.share_my_private_key();
        my_pub = alg.share_my_public_key();
        store_my_pub(my_pub);
        store_my_priv(my_priv);
    }

    void registration() {
        std::cout << "registration init " << std::endl;
        std::unique_ptr<Packet> req = std::make_unique<RegistrationRequest>(my_pub);
        send_request(*req);


        auto res = recv_response();

        auto reg_res = dynamic_cast<RegistrationResponse*>(res.get());
        if (reg_res == nullptr) {
            std::cout << "registration failed" << std::endl;
            return;
        }

        my_id = reg_res->user_id;
        std::cout << "my new id is: " << my_id << std::endl;
        // store_my_id(reg_res->user _id);
    }

    bool get_other_pub(rsa::key_t& ids_pub, int dest_id) {
        std::cout << "get_other_pub init " << std::endl;
        std::unique_ptr<Packet> req = std::make_unique<GetOtherPubRequest>(dest_id);
        // std::cout << packet_utils::hex_rep(req->serialize()) << std::endl;

        send_request(*req); 

        auto res = recv_response();

        auto pub_res = dynamic_cast<GetOtherPubResponse*>(res.get());
        if (res == nullptr) {
            std::cout << "get_other_pub failed" << std::endl;
            return false;
        }
        if (!pub_res->is_success()) {
            std::cout << "get_other_pub server not found, id:" << dest_id << std::endl;
            return false;
        }
        ids_pub = pub_res->public_key;
        store_pub_by_id(pub_res->public_key, dest_id);
        return true;
    }

    bool send_sym(int dest_id) {
        std::cout << "send_sym init " << std::endl;
        aes::key_t sym;
        aes::key_gen(sym);

        aes::store_key(std::to_string(dest_id) + "/sym.key", sym);
        rsa::key_t ids_pub;
        if (!get_pub_by_id_from_fs(ids_pub, dest_id)) {
            std::cout << "pub by id" << dest_id << "not found" << std::endl;
            if (!get_other_pub(ids_pub, dest_id)) {
                return false;
            }
        }


        std::string chiphered_key = mpz_to_string(rsa::encrypt_message(string_to_mpz(aes::serialize_key_to_string(sym)), ids_pub));
        std::unique_ptr<Packet> req = std::make_unique<SendSymRequest>(dest_id, chiphered_key);
        // std::cout << "send_sym request: " << packet_utils::hex_rep(req->serialize()) << std::endl;
        send_request(*req);      

        auto res = recv_response();

        auto sym_res = dynamic_cast<SendSymResponse*>(res.get());
        if (sym_res == nullptr) {
            std::cout << "send_sym_error" <<std::endl;
            return false;
        }

        return sym_res->is_success();
    }

    bool send_message(int dest_id, const std::string& message) {
        std::cout << "send_message init " << std::endl;
        aes::key_t sym;
        if (!get_sym_by_id_from_fs(sym, dest_id)) {
            send_sym(dest_id);
            get_sym_by_id_from_fs(sym, dest_id);
        }

        aes::Chipher chipher(sym);
        std::string chiphered_message = chipher.encrypt_string(message);


        std::unique_ptr<Packet> req = std::make_unique<MessageRequest>(dest_id, message);
        send_request(*req);

        auto res = recv_response();

        auto mes_res = dynamic_cast<MessageResponse*>(res.get());
        if (mes_res == nullptr) {
            std::cout << "send_message error" <<std::endl;
            return false;
        }
        return mes_res->is_success();

    }


};

int main() {
    try {
        asio::io_context io_context;

        Secure_Session session(io_context);

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}