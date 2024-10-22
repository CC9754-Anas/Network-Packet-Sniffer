# include "../include/packet_sniffer.hpp"


void handler(u_char* user,const struct pcap_pkthdr* pkt_hdr,const u_char* pkt_data)
{
    std::cout << "capture length: " << pkt_hdr->caplen 
              << "\ntime (s): " << pkt_hdr->ts.tv_sec 
              << " s " << pkt_hdr->ts.tv_usec << " us"
              << std::endl;
}


int main()
{
   PacketSniffer p{};
   p.choose_interface();
   auto pkt_handler = pointer_to_functor<PCAP_SIGNATURE>((void*)handler);
   p.set_callback(pkt_handler);
   p.set_filter("src host 142.250.191.110");
   p.run(1000);
}