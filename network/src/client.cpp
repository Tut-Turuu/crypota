// client.cpp
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include "server_info.hpp"
#include "random.hpp"
#include "signature.hpp"


class Connection {
private:
    int sock;
    bool is_active;

public:
    Connection(std::string adddr, int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Ошибка создания сокета\n";
            is_active = false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(get_server_port());
        
        if (inet_pton(AF_INET, get_server_addr().data(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Неверный адрес\n";
            close(sock);
            is_active = false;
        }

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Ошибка подключения\n";
            close(sock);
            is_active = false;
        }
    }

    bool verify() {
        
    }


};





// int main() {
//     // 1. Создаем сокет
//     int sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock < 0) {
//         std::cerr << "Ошибка создания сокета\n";
//         return 1;
//     }

//     // 2. Настраиваем адрес сервера
//     struct sockaddr_in server_addr;
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_port = htons(8080);
    
//     // Преобразуем IP-адрес из строки в двоичный формат
//     if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
//         std::cerr << "Неверный адрес\n";
//         close(sock);
//         return 1;
//     }

//     // 3. Подключаемся к серверу
//     if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
//         std::cerr << "Ошибка подключения\n";
//         close(sock);
//         return 1;
//     }

//     std::cout << "Подключено к серверу\n";

//     // 4. Отправляем сообщение
//     std::string message = "Привет, сервер!";
//     send(sock, message.c_str(), message.length(), 0);
//     std::cout << "Отправлено: " << message << "\n";

//     // 5. Получаем ответ
//     char buffer[1024] = {0};
//     int bytes_read = read(sock, buffer, sizeof(buffer) - 1);
//     if (bytes_read > 0) {
//         std::cout << "Получено от сервера: " << buffer << "\n";
//     }

//     // 6. Закрываем сокет
//     close(sock);
//     return 0;
// }