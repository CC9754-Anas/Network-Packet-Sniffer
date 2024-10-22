# pragma once

# include <iostream>
# include <thread>
# include <chrono>
# include <pcap.h>
# include <libnet/libnet-headers.h>
# include <libnet/libnet-macros.h>
# include <libnet/libnet-structures.h>
# include <libnet/libnet-functions.h>
# include <string.h>
# include "declarations.hpp"
# include "ip.hpp"

class Troute
{

public:


    Troute(IP ip) : ip(ip)
    {
        this->init();
    }

    Troute(Hostname hostname)
    {
        this->init();
        this->setHostname(hostname);
    }

    Troute() {
        this->init();
    }

    void setHostname(Hostname hostname)
    {
        auto hname = resolve(hostname);
        if(hname == "error")
            throw std::runtime_error("failed to resolve hostname");
        this->ip = IP{hname,IPVersion::v4};
    }

    void setIp(IP ip) 
    {
        auto hname = const_cast<char*>(ip.getIp().c_str());
        this->addr = libnet_name2addr4(this->ctx,hname,LIBNET_DONT_RESOLVE);
        if(this->addr == -1)
        {
            throw std::invalid_argument("conversion of ip to uint32_t failed");
        }

        ip.setIp(ip.getIp());
    }

    friend std::ostream& operator<<(std::ostream& oss,Troute& t)
    {
        oss << "Troute {\n\tip: " << t.ip.getIp() << "\n}" << std::endl;
        return oss;
    } 

    uint32_t getHostIp()
    {
        auto _addr = libnet_get_ipaddr4(this->ctx);
        if(_addr == -1)
            this->throw_error();
        return _addr;
    }

    libnet_ether_addr* get_mac_addr()
    {
        auto _mac_addr = libnet_get_hwaddr(this->ctx);
        if(_mac_addr == nullptr)
            this->throw_error();
        return _mac_addr;
    }

    static std::string ip_repr(uint32_t addr)
    {
        auto ip_addr_str = libnet_addr2name4(addr,  LIBNET_DONT_RESOLVE);
        std::size_t n = strlen(ip_addr_str);

        auto new_buffer = new char[n+1];
        memset(new_buffer,0x0,n);
        memcpy(new_buffer,ip_addr_str,n);

        return std::string(new_buffer);
    }

    static std::string mac_repr(libnet_ether_addr * mac_addr)
    {
        auto mac_addr_str = new char[18];
        memset(mac_addr_str,0x0,18);
        /* I was really forced to use sprintf I did not choose to use it */
        sprintf(mac_addr_str,"%02X:%02X:%02X:%02X:%02X:%02X",\
        mac_addr->ether_addr_octet[0],\
        mac_addr->ether_addr_octet[1],\
        mac_addr->ether_addr_octet[2],\
        mac_addr->ether_addr_octet[3],\
        mac_addr->ether_addr_octet[4],\
        mac_addr->ether_addr_octet[5]);
        return std::string(mac_addr_str);
    }

    libnet_ptag_t build_ipv4(uint8_t ttl,uint8_t *payload,std::size_t payload_size)
    {
        auto ip_addr = this->getHostIp();
        auto mac_addr = this->get_mac_addr();
        
        libnet_ptag_t ipv4 = 0;
        ipv4 = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,
            0x0,
            libnet_get_prand(LIBNET_PRu16),
            0x0,
            ttl,
            IPPROTO_ICMP,
            0x0,
            ip_addr, /* src ip your ip address */
            this->addr, /* dest ip web ip address */
            payload,
            payload_size,
            this->ctx,
            ipv4
            );

        if(ipv4 == -1)
            this->throw_error();
        
        return ipv4;
    }

    void throw_error()
    {
        auto err = libnet_geterror(this->ctx);
        throw std::runtime_error(std::string(err));
    }

    void write_icmp_packet(uint8_t ttl)
    {
        auto ipv4 = this->build_ipv4(ttl,nullptr, 0x0);
        if(libnet_write(this->ctx) == -1)
            this->throw_error();
    }

    void trace()
    {
        uint8_t ttl = 0x0; /* Time to live */
        while(ttl <= MAX_TTL)
        {
            std::cout << "Current ttl: " << (int)ttl << std::endl;
            write_icmp_packet(ttl);
            ttl += 1;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    ~Troute() noexcept
    {
        libnet_destroy(this->ctx);
    }

private:

    IP ip{IPVersion::v4}; /* ip address of the destination */
    std::size_t count; /* time to live */
    uint32_t addr = 0; /* numeric ip address */
    /* error buffer */
    std::unique_ptr<char> err = std::unique_ptr<char>(new char[LIBNET_ERRBUF_SIZE]);
    libnet_context *ctx; /* libnet context */


    /**
     * Resolve a hostname like google.com to a dotted decimal 
     * ip address like 10.0.10.223
    */
    std::string resolve(Hostname hostname)
    {
        auto hname = const_cast<char*>(hostname.c_str());
        uint32_t addr = libnet_name2addr4(this->ctx,hname,LIBNET_RESOLVE);

        if(addr == -1)
            return "error";

        this->addr = addr;
       
          
        return this->ip_repr(addr);
    }

    void init()
    {
        if(!isSudo())
            throw std::runtime_error("Insufficient permission to use raw packets");
        this->ctx = libnet_init(LIBNET_RAW4,nullptr, this->err.get());
        if (this->ctx == nullptr)
            throw std::runtime_error("libnet() failed: " + std::string(this->err.get()));
    }

    void intercept_packet()
    {
        
    }

};