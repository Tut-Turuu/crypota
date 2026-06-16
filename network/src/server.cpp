// server.cpp
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // 1. Создаем сокет
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Ошибка создания сокета\n";
        return 1;
    }

    // 2. Настраиваем адрес сервера
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Принимаем соединения с любого IP
    address.sin_port = htons(8080);         // Порт 8080

    // 3. Привязываем сокет к адресу
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Ошибка привязки\n";
        close(server_fd);
        return 1;
    }

    // 4. Начинаем слушать соединения (максимум 3 в очереди)
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Ошибка listen\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Сервер запущен на порту 8080\n";

    while (true) {
        // 5. Принимаем соединение
        socklen_t addrlen = sizeof(address);
        int client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        if (client_fd < 0) {
            std::cerr << "Ошибка accept\n";
            continue;
        }

        std::cout << "Клиент подключен: " << inet_ntoa(address.sin_addr) << "\n";

        // 6. Читаем и отправляем обратно (эхо)
        char buffer[1024] = {0};
        int bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            std::cout << "Получено: " << buffer;
            send(client_fd, buffer, bytes_read, 0);
        }

        // 7. Закрываем соединение
        close(client_fd);
        std::cout << "Клиент отключен\n";
    }

    close(server_fd);
    return 0;
}