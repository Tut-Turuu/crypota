#include <webview/webview.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include "../packets.hpp"


namespace asio = boost::asio;
using asio::ip::tcp;

std::string readFile(const std::string& path);
std::string build_html();

// Класс для связи GUI и сети
class ClientGUI {
private:
    webview::webview w;
    std::unique_ptr<asio::io_context> io_context;
    std::unique_ptr<tcp::socket> socket;
    bool connected = false;
    
public:
    ClientGUI() : w(true, nullptr) {
        w.set_title("Crypota - Secure Messenger");
        w.set_size(1000, 700, WEBVIEW_HINT_NONE);
        
        w.bind("connect_to_server", [this](std::string req) -> std::string {
            return handle_connect(req);
        });
        
        w.bind("send_message", [this](std::string req) -> std::string {
            return handle_send_message(req);
        });
        
        load_html();
    }
    
    void run() {
        w.run();
    }
    
private:
    std::string handle_connect(const std::string& req) {
        try {
            if (!io_context) {
                io_context = std::make_unique<asio::io_context>();
                socket = std::make_unique<tcp::socket>(*io_context);
            }
            // Парсим адрес сервера из req
            // Пример: {"host": "localhost", "port": 8080}
            // Здесь нужно добавить парсинг JSON
            
            // Подключаемся к серверу
            tcp::resolver resolver(*io_context);
            auto endpoints = resolver.resolve("localhost", "5000");
            asio::connect(*socket, endpoints);
            
            connected = true;
            
            // Запускаем сетевой поток
            std::thread([this]() {
                run_network_loop();
            }).detach();
            
            return "{\"status\": \"ok\"}";
        } catch (const std::exception& e) {
            return "{\"status\": \"error\", \"message\": \"" + std::string(e.what()) + "\"}";
        }
    }
    
    std::string handle_send_message(const std::string& req) {
        // Здесь будет логика отправки зашифрованного сообщения
        std::cout << "[GUI] Отправка сообщения: " << req << std::endl;
        return "{\"status\": \"ok\"}";
    }
    
    void load_html() {
        std::string html = build_html();
        w.set_html(html);
    }
    
    void run_network_loop() {
        try {
            io_context->run();
        } catch (const std::exception& e) {
            std::cerr << "Network error: " << e.what() << std::endl;
        }
    }
};


std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть: " << path << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string build_html() {
    std::string html = readFile("src/index.html");
    std::string css = readFile("src/styles.css");
    std::string js = readFile("src/script.js");
    
    size_t styleStart = html.find("<style>");
    size_t styleEnd = html.find("</style>");
    if (styleStart != std::string::npos && styleEnd != std::string::npos) {
        html.replace(styleStart + 7, styleEnd - styleStart - 7, css);
    }
    
    size_t scriptStart = html.find("<script>");
    size_t scriptEnd = html.find("</script>");
    if (scriptStart != std::string::npos && scriptEnd != std::string::npos) {
        html.replace(scriptStart + 8, scriptEnd - scriptStart - 8, js);
    }
    
    return html;
}

int main() {
    ClientGUI app;
    app.run();
    return 0;
}