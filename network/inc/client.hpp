#pragma once
#include <string>


class Connection {
private:
    int sock;
    bool is_active;

public:
    Connection(std::string adddr, int port);


    bool verify();


};