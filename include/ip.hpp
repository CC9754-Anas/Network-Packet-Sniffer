# pragma once

# include <iostream>
# include <vector>
# include <sstream>
# include "declarations.hpp"


class IP
{

public:

    IP(const std::string &ip_str, IPVersion version)
    {
        if (version == IPVersion::v6)
            throw std::invalid_argument("IP version 6 not supported");

        if (!this->isValidIp(ip_str))
            throw std::invalid_argument("Invalid ip format");
        
        this->version = version;
        this->str = ip_str;
    }

    IP(IPVersion version)
    {
        this->version = version;
        this->str = "127.0.0.1";
    }

    void setIp(std::string const &str) { this->str = str; }
    std::string getIp() { return this->str; }

    friend std::ostream &operator<<(std::ostream &oss, const IP &_ip)
    {
        oss << "IP {\n\tversion: " << _ip.version << "\n\tip: " << _ip.str << "\n}\n";
        return oss;
    }

private:

    std::string str = "";
    IPVersion version;

    bool isValidIp(const std::string &str)
    {
        std::vector<std::size_t> ipValues;
        std::string token;
        char separator = '.';
        auto ss = std::stringstream{str};

        while (std::getline(ss, token, separator))
        {
            std::size_t ipvalue;
            std::stringstream sstmp{token};
            sstmp >> ipvalue;
            ipValues.push_back(ipvalue);
        }

        if (ipValues.size() != 4)
            return false;

        for (auto it = ipValues.begin(); it != ipValues.end(); ++it)
        {
            if (*it > 255)
                return false;
        }

        return true;
    }
};
