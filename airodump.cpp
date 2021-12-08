#include <iostream>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <map>
#include <string>
#include <ctype.h>
#include <signal.h>
#include <pcap.h>

#include "mac.h"

#pragma pack(push,1)
typedef struct radiotapHdr
{
    uint8_t vision; //make vision to 0
    uint8_t pad;
    uint16_t len; // header length (entire length)
    uint32_t present; //field
}rtHdr;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct beaconHdr
{
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration;
    Mac dst;
    Mac src;
    Mac bssid;
    uint16_t seq;
}bHdr;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct fixed_parameter
{
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
}fP;
#pragma pack(pop)

extern bool check;
bool check = true;

using std::string;
using std::map; // pair object //map<key,value>
using std::pair; // tie two objects to be treated as one object // pair<t1,t2>



void usage()
{
    printf("syntax : airodump <interface>");
    printf("sample : airodump mon0\n");
}

void printinfo(map<Mac,pair<uint64_t,string>>& info)
{ 
    printf("BSSID / Beacons / ESSID\n");
    auto iter = info.begin();
    while(iter!=info.end())
    {
        std::cout << string(iter->first) << '	' << (iter->second).first << '	' << (iter->second).second << std::endl;
        ++iter;
    }
}

bool essidcheck(string& essid)
{
    for(char ch_ess : essid) 
    	if(isprint(ch_ess) == 0)
    		return false;
    return true;
}

void checksigint(int signo)
{
    check = false;
    putchar('\n');
}

int main(int argc,char* argv[])
{
    if(argc!=2)
    {
        usage();
        return -1;
    }
    
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    struct pcap_pkthdr* header;
    const u_char* packet;
    rtHdr* radiotap = (rtHdr*)packet;
    uint16_t radlen;
    
    if (handle == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }
    
    signal(2,checksigint); // signal(int signum, void (*handler)(int)) , 2,SIGINT => interrupt, exit process
    map<Mac,pair<uint64_t,string>> info;

    while(check)
    {
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        radlen = radiotap->len;
        bHdr* beacon = (bHdr*)(packet+radlen);

        if(beacon->subtype != 8) continue; // BEACON = 8
        Mac bssmac = beacon->bssid;
        
        fP* fixmanage = (fP*)(((u_char*)beacon)+sizeof(bHdr));
        char* tag = ((char*)fixmanage)+sizeof(fP);
        
        uint8_t essid_len = *(tag+1);
        string essid = string(tag+2,essid_len);
        auto iter = info.find(bssmac);

        if(iter == info.end())
        {
            bool Netname = essidcheck(essid);
            pair<uint64_t,string> prin;
            if(Netname)
            	prin = {1,essid};
            else
            	prin = {0,string("<length : ")+std::to_string(essid_len)+string(">")};
            	
            info[bssmac] = prin;
        }
        else ++(iter->second).first;

        printinfo(info);
    }
    pcap_close(handle);
    return 0;
}
