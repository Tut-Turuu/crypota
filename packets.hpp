#include <string>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "rsa.hpp"
#include "aes.hpp"
#include "sha256.hpp"

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

namespace packet_utils {
    std::string hex_rep(const std::string& str) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < str.size(); ++i) {
            // Добавляем пробел перед каждым 4-м байтом (кроме первого)
            if (i > 0 && i % 4 == 0) {
                ss << ' ';
            }
            
            unsigned char c = static_cast<unsigned char>(str[i]);
            ss << std::setw(2) << static_cast<int>(c);
        }
        
        return ss.str();
    }

    inline std::string number_to_string(uint32_t num) {
        std::string result(4, '\0');
        result[0] = (num >> 24) & 0xFF;
        result[1] = (num >> 16) & 0xFF;
        result[2] = (num >> 8) & 0xFF;
        result[3] = num & 0xFF;
        return result;
    }
    
    inline uint32_t string_to_number(const std::string& data, size_t offset = 0) {
        if (data.size() < offset + 4) {
            throw std::out_of_range("Not enough data");
        }
        return (static_cast<uint32_t>(static_cast<unsigned char>(data[offset])) << 24) |
               (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 1])) << 16) |
               (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 2])) << 8) |
               static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 3]));
    }

    inline std::string string_to_packet(const std::string& str) {
        uint32_t len = static_cast<uint32_t>(str.size());
        return number_to_string(len) + str;
    }

    // Извлекает строку из payload, начиная с offset, обновляет offset
    inline std::string string_from_packet(const std::string& payload, size_t& offset) {
        if (offset + 4 > payload.size()) {
            throw std::invalid_argument("Not enough data for length");
        }
        uint32_t len = string_to_number(payload, offset);
        offset += 4;
        if (offset + len > payload.size()) {
            throw std::invalid_argument("Not enough data for string content");
        }
        std::string result = payload.substr(offset, len);
        offset += len;
        return result;
    }
}

// ==================== ENUM ====================

enum class packet_type : uint32_t {
    handshake_req1,
    handshake_res1,
    handshake_req2,
    handshake_res2,
    registration_req,
    registration_res,
    message_req,
    message_res,
    get_other_pub_req,
    get_other_pub_res,
    send_sym_req,
    send_sym_res,
    ping_req,
    ping_res,
    
};

enum class status_codes : uint32_t {
    delivered,
    error,
    not_found
};

// ==================== БАЗОВЫЙ КЛАСС ====================

struct Packet {
    virtual ~Packet() = default;
    
    virtual std::string serialize() const = 0;
    virtual packet_type type() const = 0;
    virtual std::string to_string() const = 0;
    
    // Фабрика
    static std::unique_ptr<Packet> from_payload(const std::string& payload);
    static std::unique_ptr<Packet> from_raw(const std::string& raw);
};



std::string hmac_packet(const std::string& serialized_packet, const std::string& session_secret) {
    // 1. Вычисляем HMAC (SHA-256 от пакета + секрет)
    std::string data_to_hash = serialized_packet + session_secret;
    std::string hash = sha256(data_to_hash);
    
    // 2. Формируем финальный пакет: [длина][serialized_packet][hash]
    // Длина = длина serialized_packet + длина хэша (64 байта для hex-строки)
    uint32_t total_length = serialized_packet.length() + hash.length();
    
    // Создаем бинарное представление длины (4 байта, big-endian)

    
    std::string result;
    result += packet_utils::number_to_string(total_length);
    result.append(serialized_packet);
    result.append(hash);
    
    return result;
}

bool verify_hmac(const std::string& serialized_packet, const std::string& session_secret) {
    // Проверяем, что пакет достаточно длинный (минимум 4 байта длины + 64 байта хэша)
    if (serialized_packet.length() < 4 + 32) {
        return false;
    }
    
    // 1. Извлекаем длину из первых 4 байт
    
    uint32_t total_length = packet_utils::string_to_number(serialized_packet, 0);
    
    // Проверяем, что длина соответствует размеру пакета
    if (total_length != serialized_packet.length() - 4) {
        return false;
    }
    
    // 2. Извлекаем сам пакет (все что между длиной и хэшем)
    // Хэш всегда SHA-256 в hex-строке = 64 байта
    size_t hash_start = 4 + total_length - 32;
    if (hash_start < 4 || hash_start > serialized_packet.length()) {
        return false;
    }
    
    std::string packet_data = serialized_packet.substr(4, total_length - 32);
    std::string received_hash = serialized_packet.substr(hash_start, 32);
    
    // 3. Вычисляем хэш от пакета с секретом
    std::string data_to_hash = packet_data + session_secret;
    std::string computed_hash = sha256(data_to_hash);
    
    // 4. Сравниваем хэши (константное сравнение для защиты от timing attacks)

    // std::cout << "Hmac recived: " << packet_utils::hex_rep(received_hash) << "Hmac computed: " << packet_utils::hex_rep(computed_hash) << std::endl;
    return computed_hash == received_hash;
}

std::string get_raw_packet(const std::string& serialized_packet) {
    // Проверяем минимальную длину пакета
    if (serialized_packet.length() < 4 + 32) {
        return ""; // или throw exception
    }
    
    // Извлекаем длину из первых 4 байт
    uint32_t total_length = packet_utils::string_to_number(serialized_packet, 0);
    
    // Проверяем, что длина соответствует размеру пакета
    if (total_length != serialized_packet.length() - 4) {
        return ""; // или throw exception
    }
    
    // Извлекаем внутренний пакет (без длины и хэша)
    size_t hash_start = 4 + total_length - 32;
    if (hash_start < 4 || hash_start > serialized_packet.length()) {
        return "";
    }
    
    return serialized_packet.substr(4, total_length - 32);
}


struct HandshakeRequest1 : public Packet {
    std::string client_random;
    uint32_t user_id = 0;

    HandshakeRequest1() = default;
    HandshakeRequest1(std::string cr, uint32_t uid)
        : client_random(std::move(cr)), user_id(uid) {}

    packet_type type() const override {
        return packet_type::handshake_req1;   // добавьте в enum
    }

    std::string serialize() const override {
        // Формат: [type(4)] [client_random_len(4)+data] [user_id(4)]
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type()));
        payload += packet_utils::string_to_packet(client_random);
        payload += packet_utils::number_to_string(user_id);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }

    std::string to_string() const override {
        return "HandshakeRequest1{client_random=" + client_random +
               ", user_id=" + std::to_string(user_id) + "}";
    }

    static std::unique_ptr<HandshakeRequest1> from_payload(const std::string& payload) {
        // Минимум: type(4) + length(4) + user_id(4) = 12 байт (если строка не пустая)
        if (payload.size() < 12) {
            throw std::invalid_argument("Payload too small for HandshakeRequest1");
        }

        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::handshake_req1)) {
            throw std::invalid_argument("Invalid packet type");
        }

        size_t offset = 4;
        auto req = std::make_unique<HandshakeRequest1>();
        req->client_random = packet_utils::string_from_packet(payload, offset);
        req->user_id = packet_utils::string_to_number(payload, offset);
        offset += 4;

        if (req->client_random.empty()) {
            throw std::invalid_argument("Empty client_random");
        }


        return req;
    }
};

// ============================================================================
// 2. HandshakeResponse1 (первый ответ)
// ============================================================================
struct HandshakeResponse1 : public Packet {
    status_codes status = status_codes::error;
    std::string server_random;
    std::string signature;   // подпись сервера

    HandshakeResponse1() = default;

    // Конструктор для успешного ответа
    explicit HandshakeResponse1(const std::string& srv_rand, const std::string& sig)
        : status(status_codes::delivered)
        , server_random(srv_rand)
        , signature(sig) {}

    // Конструктор для ответа с ошибкой
    explicit HandshakeResponse1(status_codes st)
        : status(st)
        , server_random("")
        , signature("") {}

    packet_type type() const override {
        return packet_type::handshake_res1;   // добавьте в enum
    }

    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type()));
        payload += packet_utils::number_to_string(static_cast<uint32_t>(status));
        payload += packet_utils::string_to_packet(server_random);
        payload += packet_utils::string_to_packet(signature);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }

    std::string to_string() const override {
        if (status == status_codes::delivered) {
            return "HandshakeResponse1{status=delivered, server_random=" + server_random +
                   ", signature=" + signature + "}";
        } else {
            return "HandshakeResponse1{status=" + std::to_string(static_cast<uint32_t>(status)) + "}";
        }
    }

    static std::unique_ptr<HandshakeResponse1> from_payload(const std::string& payload) {
        // Минимум: type(4) + status(4) + две длины(8) = 16 байт (если строки не пустые)
        if (payload.size() < 16) {
            throw std::invalid_argument("Payload too small for HandshakeResponse1");
        }

        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::handshake_res1)) {
            throw std::invalid_argument("Invalid packet type");
        }

        uint32_t status_val = packet_utils::string_to_number(payload, 4);
        if (status_val > 2) {
            throw std::invalid_argument("Invalid status code");
        }

        auto resp = std::make_unique<HandshakeResponse1>();
        resp->status = static_cast<status_codes>(status_val);

        if (status_val == static_cast<uint32_t>(status_codes::delivered)) {
            size_t offset = 8;
            resp->server_random = packet_utils::string_from_packet(payload, offset);
            resp->signature = packet_utils::string_from_packet(payload, offset);

            if (resp->server_random.empty() || resp->signature.empty()) {
                throw std::invalid_argument("Missing server_random or signature in success response");
            }
        }
        return resp;
    }

    // Фабричные методы
    static std::unique_ptr<Packet> success(const std::string& srv_rand, const std::string& sig) {
        return std::make_unique<HandshakeResponse1>(srv_rand, sig);
    }

    static std::unique_ptr<Packet> error() {
        return std::make_unique<HandshakeResponse1>(status_codes::error);
    }

    static std::unique_ptr<Packet> not_found() {
        return std::make_unique<HandshakeResponse1>(status_codes::not_found);
    }

    bool is_success() const { return status == status_codes::delivered; }
};

// ============================================================================
// 3. HandshakeRequest2 (второй запрос)
// ============================================================================
struct HandshakeRequest2 : public Packet {
    std::string signature;                // подпись клиента
    std::string encrypted_session_id;     // зашифрованный session_id

    HandshakeRequest2() = default;
    HandshakeRequest2(std::string sig, std::string enc)
        : signature(std::move(sig))
        , encrypted_session_id(std::move(enc)) {}

    packet_type type() const override {
        return packet_type::handshake_req2;   // добавьте в enum
    }

    std::string serialize() const override {
        // Формат: [type(4)] [signature_len(4)+data] [encrypted_session_id_len(4)+data]
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type()));
        payload += packet_utils::string_to_packet(signature);
        payload += packet_utils::string_to_packet(encrypted_session_id);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }

    std::string to_string() const override {
        return "HandshakeRequest2{signature=" + signature +
               ", encrypted_session_id=" + encrypted_session_id + "}";
    }

    static std::unique_ptr<HandshakeRequest2> from_payload(const std::string& payload) {
        // Минимум: type(4) + две длины(8) = 12 байт
        if (payload.size() < 12) {
            throw std::invalid_argument("Payload too small for HandshakeRequest2");
        }

        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::handshake_req2)) {
            throw std::invalid_argument("Invalid packet type");
        }

        size_t offset = 4;
        auto req = std::make_unique<HandshakeRequest2>();
        req->signature = packet_utils::string_from_packet(payload, offset);
        req->encrypted_session_id = packet_utils::string_from_packet(payload, offset);

        if (req->signature.empty() || req->encrypted_session_id.empty()) {
            throw std::invalid_argument("Empty field in HandshakeRequest2");
        }

        return req;
    }
};

// ============================================================================
// 4. HandshakeResponse2 (второй ответ) - только статус
// ============================================================================
struct HandshakeResponse2 : public Packet {
    status_codes status = status_codes::error;

    HandshakeResponse2() = default;
    explicit HandshakeResponse2(status_codes st) : status(st) {}

    packet_type type() const override {
        return packet_type::handshake_res2;   // добавьте в enum
    }

    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type()));
        payload += packet_utils::number_to_string(static_cast<uint32_t>(status));
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }

    std::string to_string() const override {
        return "HandshakeResponse2{status=" + std::to_string(static_cast<uint32_t>(status)) + "}";
    }

    static std::unique_ptr<HandshakeResponse2> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small for HandshakeResponse2");
        }

        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::handshake_res2)) {
            throw std::invalid_argument("Invalid packet type");
        }

        uint32_t status_val = packet_utils::string_to_number(payload, 4);
        if (status_val > 2) {
            throw std::invalid_argument("Invalid status code");
        }

        auto resp = std::make_unique<HandshakeResponse2>();
        resp->status = static_cast<status_codes>(status_val);
        return resp;
    }

    // Фабричные методы
    static std::unique_ptr<Packet> success() {
        return std::make_unique<HandshakeResponse2>(status_codes::delivered);
    }

    static std::unique_ptr<Packet> error() {
        return std::make_unique<HandshakeResponse2>(status_codes::error);
    }

    static std::unique_ptr<Packet> not_found() {
        return std::make_unique<HandshakeResponse2>(status_codes::not_found);
    }

    bool is_success() const { return status == status_codes::delivered; }
};

// 1. Registration Request
struct RegistrationRequest : public Packet {
    rsa::key_t public_key;
    
    RegistrationRequest() = default;
    explicit RegistrationRequest(const rsa::key_t& key) : public_key(key) {}
    
    packet_type type() const override { return packet_type::registration_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              rsa::serialize_key_to_string(public_key);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "RegistrationRequest{public_key_size=" + 
               std::to_string(rsa::serialize_key_to_string(public_key).size()) + "}";
    }
    
    static std::unique_ptr<RegistrationRequest> from_payload(const std::string& payload) {
        if (payload.size() < 4) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::registration_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<RegistrationRequest>();
        req->public_key = rsa::deserialize_string_to_key(payload.substr(4));
        
        if (rsa::serialize_key_to_string(req->public_key).empty()) {
            throw std::invalid_argument("Empty public key");
        }
        
        return req;
    }
};

// 2. Registration Response
struct RegistrationResponse : public Packet {
    uint32_t user_id = 0;
    
    RegistrationResponse() = default;
    explicit RegistrationResponse(uint32_t id) : user_id(id) {}
    
    packet_type type() const override { return packet_type::registration_res; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(user_id);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "RegistrationResponse{user_id=" + std::to_string(user_id) + "}";
    }
    
    static std::unique_ptr<RegistrationResponse> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::registration_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto resp = std::make_unique<RegistrationResponse>();
        resp->user_id = packet_utils::string_to_number(payload, 4);
        
        return resp;
    }
};

// 3. Message Request
struct MessageRequest : public Packet {
    uint32_t dest_id = 0;
    uint32_t source_id = 0;
    std::string message;
    
    MessageRequest() = default;
    MessageRequest(uint32_t dest, uint32_t source, const std::string& msg) 
        : dest_id(dest), source_id(source), message(msg) {}
    
    packet_type type() const override { return packet_type::message_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(dest_id) +
                              packet_utils::number_to_string(source_id) +
                              message;
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "MessageRequest{dest_id=" + std::to_string(dest_id) + " source_id=" + std::to_string(source_id) +
               ", msg_size=" + std::to_string(message.size()) + "}";
    }
    
    static std::unique_ptr<MessageRequest> from_payload(const std::string& payload) {
        if (payload.size() < 12) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::message_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<MessageRequest>();
        req->dest_id = packet_utils::string_to_number(payload, 4);
        req->source_id = packet_utils::string_to_number(payload, 8);
        req->message = payload.substr(12);
        
        if (req->message.empty()) {
            throw std::invalid_argument("Message cannot be empty");
        }
        
        return req;
    }
};

// 4. Message Response
struct MessageResponse : public Packet {
    status_codes status_code = status_codes::delivered;
    uint32_t dest_id = 0;  // ← Добавил
    uint32_t source_id = 0;

    MessageResponse() = default;

    MessageResponse(uint32_t dest, uint32_t source, status_codes code) : status_code(code), dest_id(dest), source_id(source) {}
    
    packet_type type() const override { return packet_type::message_res; }
    
    std::string serialize() const override {
        // Формат: [type(4)] [status_code(4)] [dest_id(4)]
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(dest_id) +
                              packet_utils::number_to_string(source_id) +
                              packet_utils::number_to_string(static_cast<uint32_t>(status_code))
                              ;
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "MessageResponse{dest_id=" + std::to_string(dest_id) + ", source_id=" + std::to_string(source_id) + ", status_code=" + std::to_string(static_cast<uint32_t>(status_code)) + "}";
    }
    
    static std::unique_ptr<MessageResponse> from_payload(const std::string& payload) {
        // Минимум: type(4) + status(4) + dest_id(4) = 12 байт
        if (payload.size() < 12) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::message_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        
        uint32_t dest = packet_utils::string_to_number(payload, 4);
        uint32_t source = packet_utils::string_to_number(payload, 8);
        uint32_t code = packet_utils::string_to_number(payload, 12);
        
        auto resp = std::make_unique<MessageResponse>();
        resp->status_code = static_cast<status_codes>(code);
        resp->dest_id = dest;
        resp->source_id = source;
        
        return resp;
    }

    bool is_success() const { return status_code == status_codes::delivered; }
    
    // Фабричные методы для удобства
    static std::unique_ptr<Packet> success(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<MessageResponse>(dest_id, source_id, status_codes::delivered);
    }
    
    static std::unique_ptr<Packet> error(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<MessageResponse>(dest_id, source_id, status_codes::error);
    }
    
    static std::unique_ptr<Packet> not_found(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<MessageResponse>(dest_id, source_id, status_codes::not_found);
    }
};

// 5. Get Other Public Key Request
struct GetOtherPubRequest : public Packet {
    uint32_t target_user_id = 0;
    
    GetOtherPubRequest() = default;
    explicit GetOtherPubRequest(uint32_t id) : target_user_id(id) {}
    
    packet_type type() const override { return packet_type::get_other_pub_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(target_user_id);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "GetOtherPubRequest{target_user_id=" + std::to_string(target_user_id) + "}";
    }
    
    static std::unique_ptr<GetOtherPubRequest> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::get_other_pub_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<GetOtherPubRequest>();
        req->target_user_id = packet_utils::string_to_number(payload, 4);
        
        if (req->target_user_id == 0) {
            throw std::invalid_argument("Invalid target user ID");
        }
        
        return req;
    }
};


struct GetOtherPubResponse : public Packet {
    rsa::key_t public_key;
    status_codes status = status_codes::delivered;
    uint32_t dest_id = 0;  // ← добавил поле
    
    GetOtherPubResponse() = default;
    explicit GetOtherPubResponse(status_codes code) 
        :  status(code) {}
    GetOtherPubResponse(const rsa::key_t& key, uint32_t id) 
        : public_key(key), status(status_codes::delivered), dest_id(id) {}
    
    packet_type type() const override { return packet_type::get_other_pub_res; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(static_cast<uint32_t>(status)) +
                              packet_utils::number_to_string(dest_id) +
                              rsa::serialize_key_to_string(public_key);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        if (status == status_codes::delivered) {
            return "GetOtherPubResponse{status=delivered, dest_id=" + 
                   std::to_string(dest_id) + 
                   ", key_size=" + 
                   std::to_string(rsa::serialize_key_to_string(public_key).size()) + "}";
        } else {
            return "GetOtherPubResponse{status=" + std::to_string(static_cast<uint32_t>(status)) + 
                   ", dest_id=" + std::to_string(dest_id) + "}";
        }
    }
    
    static std::unique_ptr<GetOtherPubResponse> from_payload(const std::string& payload) {
        if (payload.size() < 12) {  // type(4) + status(4) + dest_id(4)
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::get_other_pub_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        uint32_t status_val = packet_utils::string_to_number(payload, 4);
        auto status = static_cast<status_codes>(status_val);
        
        uint32_t dest_id_val = packet_utils::string_to_number(payload, 8);
        
        auto resp = std::make_unique<GetOtherPubResponse>();
        resp->status = status;
        resp->dest_id = dest_id_val;
        
        if (status == status_codes::delivered) {
            if (payload.size() < 12) {
                throw std::invalid_argument("Missing key data");
            }
            resp->public_key = rsa::deserialize_string_to_key(payload.substr(12));
            if (rsa::serialize_key_to_string(resp->public_key).empty()) {
                throw std::invalid_argument("Empty public key");
            }
        }
        
        return resp;
    }
    
    bool is_success() const { return status == status_codes::delivered; }
    
    static std::unique_ptr<GetOtherPubResponse> not_found() {
        return std::make_unique<GetOtherPubResponse>(status_codes::not_found);
    }
    
    // static std::unique_ptr<GetOtherPubResponse> error() {
    //     return std::make_unique<GetOtherPubResponse>(status_codes::error);
    // }
};

// 7. Send Sym Request
struct SendSymRequest : public Packet {
    uint32_t dest_id = 0;
    uint32_t source_id = 0;

    std::string encrypted_sym_key;
    
    SendSymRequest() = default;
    SendSymRequest(uint32_t dest, uint32_t source, const std::string& encr_key) 
        : dest_id(dest), source_id(source), encrypted_sym_key(encr_key) {}

    
    packet_type type() const override { return packet_type::send_sym_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(dest_id) +
                              packet_utils::number_to_string(source_id) +
                              encrypted_sym_key;
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "SendSymRequest{dest_id=" + std::to_string(dest_id) + ", source_id=" + std::to_string(source_id) +
               ", encrypted_key_size=" + std::to_string(encrypted_sym_key.size()) + "}";
    }
    
    static std::unique_ptr<SendSymRequest> from_payload(const std::string& payload) {
        if (payload.size() < 12) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::send_sym_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<SendSymRequest>();
        req->dest_id = packet_utils::string_to_number(payload, 4);
        req->source_id = packet_utils::string_to_number(payload, 8);
        req->encrypted_sym_key = payload.substr(12);
        

        if (req->encrypted_sym_key.empty()) {
            throw std::invalid_argument("Encrypted key cannot be empty");
        }
        
        return req;
    }
};

// 8. Send Sym Response
struct SendSymResponse : public Packet {
    status_codes status_code = status_codes::delivered;
    uint32_t dest_id = 0;
    uint32_t source_id = 0;
    
    SendSymResponse() = default;
    SendSymResponse(uint32_t dest, uint32_t source, status_codes code) : dest_id(dest), source_id(source), status_code(code) {}
    
    packet_type type() const override { return packet_type::send_sym_res; }
    
    std::string serialize() const override {
        
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(dest_id) +
                              packet_utils::number_to_string(source_id) +
                              packet_utils::number_to_string(static_cast<uint32_t>(status_code));
                              
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "SendSymResponse{status_code=" + std::to_string(static_cast<uint32_t>(status_code)) +
               ", source_id=" + std::to_string(source_id) + "}";
    }
    
    static std::unique_ptr<SendSymResponse> from_payload(const std::string& payload) {

        if (payload.size() < 16) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::send_sym_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        uint32_t dest = packet_utils::string_to_number(payload, 4);
        uint32_t source = packet_utils::string_to_number(payload, 8);
        uint32_t code = packet_utils::string_to_number(payload, 12);
        auto resp = std::make_unique<SendSymResponse>();
        resp->dest_id = dest;
        resp->source_id = source;
        resp->status_code = static_cast<status_codes>(code);
        
        
        return resp;
    }

    bool is_success() const { return status_code == status_codes::delivered; }
    
    // Фабричные методы для удобства
    static std::unique_ptr<Packet> success(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<SendSymResponse>(dest_id, source_id, status_codes::delivered);
    }
    
    static std::unique_ptr<Packet> error(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<SendSymResponse>(dest_id, source_id, status_codes::delivered);
    }
    
    static std::unique_ptr<Packet> not_found(uint32_t dest_id, uint32_t source_id) {
        return std::make_unique<SendSymResponse>(dest_id, source_id, status_codes::delivered);
    }
};

// ==================== ФАБРИКА ====================

std::unique_ptr<Packet> Packet::from_payload(const std::string& payload) {
    if (payload.size() < 4) {
        throw std::invalid_argument("Payload too small");
    }
    
    uint32_t type_val = packet_utils::string_to_number(payload, 0);
    packet_type type = static_cast<packet_type>(type_val);
    
    switch (type) {
        case packet_type::registration_req:
            return RegistrationRequest::from_payload(payload);
        case packet_type::registration_res:
            return RegistrationResponse::from_payload(payload);
        case packet_type::message_req:
            return MessageRequest::from_payload(payload);
        case packet_type::message_res:
            return MessageResponse::from_payload(payload);
        case packet_type::get_other_pub_req:
            return GetOtherPubRequest::from_payload(payload);
        case packet_type::get_other_pub_res:
            return GetOtherPubResponse::from_payload(payload);
        case packet_type::send_sym_req:
            return SendSymRequest::from_payload(payload);
        case packet_type::send_sym_res:
            return SendSymResponse::from_payload(payload);
        case packet_type::handshake_req1:
            return HandshakeRequest1::from_payload(payload);
        case packet_type::handshake_res1:
            return HandshakeResponse1::from_payload(payload);
        case packet_type::handshake_req2:
            return HandshakeRequest2::from_payload(payload);
        case packet_type::handshake_res2:
            return HandshakeResponse2::from_payload(payload);
        default:
            throw std::invalid_argument("Unknown packet type: " + std::to_string(type_val));
    }
}

std::unique_ptr<Packet> Packet::from_raw(const std::string& raw) {
    if (raw.size() < 4) {
        throw std::invalid_argument("Raw data too small");
    }
    
    uint32_t payload_size = packet_utils::string_to_number(raw, 0);
    if (raw.size() != 4 + payload_size) {
        throw std::invalid_argument("Invalid packet size");
    }
    
    std::string payload = raw.substr(4);
    return from_payload(payload);
}