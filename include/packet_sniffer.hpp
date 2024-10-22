# pragma once

# include <iostream>
# include <cstring>
# include <functional>
# include <memory>
# include <sstream>
# include <pcap/pcap.h>
# include <sys/types.h>
# include <vector>
# include "declarations.hpp"

class PacketSniffer
{

private:
    using packet = const u_char*;
    using net_interface = pcap_if_t;
    /* Error buffer */
    std::unique_ptr<char> err = std::unique_ptr<char>(new char[PCAP_ERRBUF_SIZE]{0x0});
    bpf_program filter_program; /* berkeley packet filter program */
    bpf_u_int32 net_ip; /* ip address */
    bpf_u_int32 net_mask; /* subnet mask */
    pcap_if_t *selected_iface = nullptr;
    pcap_t* live_handle;
    std::function<PCAP_SIGNATURE> callback = nullptr;

    void throw_error()
    {
        auto err_buff = pcap_geterr(live_handle);
        memcpy(err.get(), err_buff, PCAP_ERRBUF_SIZE);
        throw std::runtime_error(std::string(err.get()));
    }

    bool get_interfaces(pcap_if_t** alldevs)
    {
        if(pcap_findalldevs(alldevs, err.get()) == -1)
        {
            return false;
        }
        return true;
    }

    std::string input(const std::string& prompt)
    {
        std::string str;
        std::cout << prompt;
        std::getline(std::cin,str);
        return str;
    }

    std::vector<net_interface*> list_interfaces(pcap_if_t** alldevs)
    {
        std::vector<net_interface*> device_list;
        for(auto i = *alldevs; i != nullptr; i = i->next)
            device_list.push_back(i);
        return device_list;
    }

    void display_interfaces(std::vector<net_interface*>& if_list)
    {
        std::size_t count = 0x0;
        std::cout << "*****\t\t Available devices \t\t***** " << std::endl;
        for(const auto& iface: if_list)
        {
            std::cout << "[" << count++ << "]" << " Device:\n"
                      << "\tname: " << iface->name
                      << "\n\tdescription: " << ((iface->description == nullptr) ? (char*)"" : iface->description)
                      << "\n\tflags: " << "0x" << std::hex << iface->flags
                      << std::endl;
        }
    }

    pcap_if_t* select_interface()
    {
        std::size_t choice = -1;
        pcap_if_t* alldevs = nullptr;
        if(!get_interfaces(&alldevs))
            throw_error();

        auto ifaces = list_interfaces(&alldevs);
        display_interfaces(ifaces);


        while(choice > (ifaces.size()-1))
        {
            auto res = input("Enter index of device to list on: ");
            auto ss = std::stringstream{res};
            ss >> choice;

            if(choice > (ifaces.size()-1))
                std::cout << "Index should be in range [0-" 
                          << ifaces.size()-1 << "]" 
                          << std::endl;
        }

        return ifaces[choice];
    }

public:

    PacketSniffer() {
        memset(err.get(),0x0,PCAP_ERRBUF_SIZE+1);
    }


    void choose_interface()
    {
        selected_iface = select_interface();
    }

    void set_callback(std::function<void(u_char*,const struct pcap_pkthdr*,const u_char*)>& callback)
    {
        this->callback = callback;
    }

    /* Convert struct sockaddr to uint32_t*/
    uint32_t sockaddr2uint(sockaddr *addr)
    {
        if(addr == nullptr)
            std::cout << "Addr is null" << std::endl;
        auto a = (sockaddr_in*)(addr);
        return a->sin_addr.s_addr;
    }

    void set_filter(const std::string &str)
    {
        live_handle = pcap_open_live(selected_iface->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,err.get());
        if(live_handle == nullptr)
            throw_error();

        if(pcap_lookupnet(selected_iface->name,&net_ip,&net_mask,nullptr) == PCAP_ERROR)
            throw_error();
        
        if(pcap_compile(live_handle,&filter_program,str.c_str(),(int)net_ip, net_mask) == PCAP_ERROR)
            throw_error();

        if(pcap_setfilter(live_handle, &filter_program) == PCAP_ERROR)
            throw_error();
    }

    /* runs */
    void run(int duration)
    {
        if(live_handle == nullptr)
            throw std::runtime_error("No open handle for live capture. Did you call set_filter?");
        auto fptr = callback.target<void(*)(u_char*,const struct pcap_pkthdr*,const u_char*)>();
        if(fptr == nullptr)
            std::cout << "fptr is null" << std::endl;
        pcap_loop(live_handle,duration,*fptr,nullptr);
    }


    ~PacketSniffer() noexcept {
        if(live_handle != nullptr)
            pcap_close(live_handle);
    }

};

