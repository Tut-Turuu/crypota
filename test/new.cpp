#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <unordered_map>
#include <memory>
#include <chrono>

namespace asio = boost::asio;
using boost::system::error_code;

// Вынесем тип канала в алиас для читаемости
using MyChannel = asio::experimental::channel<void(error_code, bool)>;

int main() {
    // Храним каналы через shared_ptr, как у вас в примере
    std::unordered_map<int, std::shared_ptr<MyChannel>> mapa;
    asio::io_context ctxt;

    // Создаем канал с ID = 1
    mapa.try_emplace(1, std::make_shared<MyChannel>(ctxt.get_executor()));

    // Получаем shared_ptr на конкретный канал, чтобы безопасно захватить его в корутины
    auto channel_ptr = mapa[1];

    // Корутина, которая отправляет значение
    // Захватываем channel_ptr по значению [channel_ptr], чтобы он не удалился
    asio::co_spawn(ctxt, [channel_ptr]() -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;
        asio::steady_timer timer(executor, std::chrono::seconds(2));
        
        co_await timer.async_wait(asio::use_awaitable);
        std::cout << "Sending value..." << std::endl;
        
        // Отправляем СТРОКУ, так как канал настроен на std::string
        co_await channel_ptr->async_send(error_code{}, true, asio::use_awaitable);
    }, asio::detached);

    // Корутина, которая ждет значение
    asio::co_spawn(ctxt, [channel_ptr]() -> asio::awaitable<void> {
        std::cout << "Waiting for value..." << std::endl;
        
        // Используем правильный метод async_receive
        // Метод возвращает строку, так как это тип данных в сигнатуре канала
        auto result = co_await channel_ptr->async_receive(asio::use_awaitable);
        
        std::cout << "Got value: " << result << std::endl;
    }, asio::detached);

    ctxt.run();
    return 0;
}