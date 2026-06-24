#include <string>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include "rsa.hpp"
#include "aes.hpp"

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

namespace packet_utils {
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
}

// ==================== ENUM ====================

enum class packet_type : uint32_t {
    registration_req = 0x01,
    registration_res = 0x02,
    message_req = 0x03,
    message_res = 0x04,
    get_other_pub_req = 0x05,
    get_other_pub_res = 0x06,
    send_sym_req = 0x07,
    send_sym_res = 0x08
};

enum class status_codes : uint32_t {
    delivered = 0,
    error = 1,
    not_found = 2
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

// ==================== ВСЕ ПАКЕТЫ ====================

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
        
        if (resp->user_id == 0) {
            throw std::invalid_argument("Invalid user ID");
        }
        
        return resp;
    }
};

// 3. Message Request
struct MessageRequest : public Packet {
    uint32_t destination_id = 0;
    std::string message;
    
    MessageRequest() = default;
    MessageRequest(uint32_t dest_id, const std::string& msg) 
        : destination_id(dest_id), message(msg) {}
    
    packet_type type() const override { return packet_type::message_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(destination_id) +
                              message;
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "MessageRequest{dest_id=" + std::to_string(destination_id) +
               ", msg_size=" + std::to_string(message.size()) + "}";
    }
    
    static std::unique_ptr<MessageRequest> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::message_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<MessageRequest>();
        req->destination_id = packet_utils::string_to_number(payload, 4);
        req->message = payload.substr(8);
        
        if (req->destination_id == 0) {
            throw std::invalid_argument("Invalid destination ID");
        }
        if (req->message.empty()) {
            throw std::invalid_argument("Message cannot be empty");
        }
        
        return req;
    }
};

// 4. Message Response
struct MessageResponse : public Packet {
    status_codes status_code = status_codes::delivered;
    
    MessageResponse() = default;
    explicit MessageResponse(status_codes code) : status_code(code) {}
    explicit MessageResponse(uint32_t code) : status_code(static_cast<status_codes>(code)) {}
    
    packet_type type() const override { return packet_type::message_res; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(static_cast<uint32_t>(status_code));
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "MessageResponse{status_code=" + std::to_string(static_cast<uint32_t>(status_code)) + "}";
    }
    
    static std::unique_ptr<MessageResponse> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::message_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        uint32_t code = packet_utils::string_to_number(payload, 4);
        
        auto resp = std::make_unique<MessageResponse>();
        resp->status_code = static_cast<status_codes>(code);
        
        // Проверка что код валидный
        if (code > 2) {
            throw std::invalid_argument("Invalid status code");
        }
        
        return resp;
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

// 6. Get Other Public Key Response
struct GetOtherPubResponse : public Packet {
    rsa::key_t public_key;
    
    GetOtherPubResponse() = default;
    explicit GetOtherPubResponse(const rsa::key_t& key) : public_key(key) {}
    
    packet_type type() const override { return packet_type::get_other_pub_res; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              rsa::serialize_key_to_string(public_key);
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "GetOtherPubResponse{public_key_size=" + 
               std::to_string(rsa::serialize_key_to_string(public_key).size()) + "}";
    }
    
    static std::unique_ptr<GetOtherPubResponse> from_payload(const std::string& payload) {
        if (payload.size() < 4) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::get_other_pub_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto resp = std::make_unique<GetOtherPubResponse>();
        resp->public_key = rsa::deserialize_string_to_key(payload.substr(4));
        
        if (rsa::serialize_key_to_string(resp->public_key).empty()) {
            throw std::invalid_argument("Empty public key");
        }
        
        return resp;
    }
};

// 7. Send Sym Request
struct SendSymRequest : public Packet {
    uint32_t destination_id = 0;
    std::string encrypted_sym_key;
    
    SendSymRequest() = default;
    SendSymRequest(uint32_t dest_id, const std::string& encr_key) 
        : destination_id(dest_id), encrypted_sym_key(enc_key) {}

    
    packet_type type() const override { return packet_type::send_sym_req; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(destination_id) +
                              encrypted_sym_key;
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "SendSymRequest{dest_id=" + std::to_string(destination_id) +
               ", encrypted_key_size=" + std::to_string(encrypted_sym_key.size()) + "}";
    }
    
    static std::unique_ptr<SendSymRequest> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::send_sym_req)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        auto req = std::make_unique<SendSymRequest>();
        req->destination_id = packet_utils::string_to_number(payload, 4);
        req->encrypted_sym_key = payload.substr(8);
        
        if (req->destination_id == 0) {
            throw std::invalid_argument("Invalid destination ID");
        }
        if (req->encrypted_sym_key.empty()) {
            throw std::invalid_argument("Encrypted key cannot be empty");
        }
        
        return req;
    }
    
    aes::key_t get_decrypted_key() const {
        return aes::deserialize_string_to_key(encrypted_sym_key);
    }
};

// 8. Send Sym Response
struct SendSymResponse : public Packet {
    status_codes status_code = status_codes::delivered;
    
    SendSymResponse() = default;
    explicit SendSymResponse(status_codes code) : status_code(code) {}
    explicit SendSymResponse(uint32_t code) : status_code(static_cast<status_codes>(code)) {}
    
    packet_type type() const override { return packet_type::send_sym_res; }
    
    std::string serialize() const override {
        std::string payload = packet_utils::number_to_string(static_cast<uint32_t>(type())) +
                              packet_utils::number_to_string(static_cast<uint32_t>(status_code));
        return packet_utils::number_to_string(static_cast<uint32_t>(payload.size())) + payload;
    }
    
    std::string to_string() const override {
        return "SendSymResponse{status_code=" + std::to_string(static_cast<uint32_t>(status_code)) + "}";
    }
    
    static std::unique_ptr<SendSymResponse> from_payload(const std::string& payload) {
        if (payload.size() < 8) {
            throw std::invalid_argument("Payload too small");
        }
        
        uint32_t type_val = packet_utils::string_to_number(payload, 0);
        if (type_val != static_cast<uint32_t>(packet_type::send_sym_res)) {
            throw std::invalid_argument("Invalid packet type");
        }
        
        uint32_t code = packet_utils::string_to_number(payload, 4);
        
        if (code > 2) {
            throw std::invalid_argument("Invalid status code");
        }
        
        auto resp = std::make_unique<SendSymResponse>();
        resp->status_code = static_cast<status_codes>(code);
        
        return resp;
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