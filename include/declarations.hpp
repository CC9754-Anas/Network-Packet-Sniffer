# pragma once

# include <string>
# include <stdint.h>
# include <unistd.h>
# include <functional>
# include <stdexcept>
# include <pcap/pcap.h>

constexpr uint8_t MAX_TTL = 0x4B;

using IPVersion = enum {
    v4 = 0x004,
    v6 = 0x006
};

using Hostname = std::string;

using PCAP_SIGNATURE = void(u_char*,const struct pcap_pkthdr*,const u_char*);

inline bool isSudo()
{
    uid_t uid = getuid();
    return (uid != 0) ? false : true;
}

template<typename Signature>
std::function<Signature> pointer_to_functor(void* fptr){
    if(fptr == nullptr)
        std::runtime_error("Function pointer cannot be null");
    return reinterpret_cast<Signature*>(fptr);
}

