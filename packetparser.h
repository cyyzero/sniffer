#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <cstdint>
#include <memory>

#define EthernetTypeIPv4 ((uint16_t)0x0800)
#define EthernetTypeARP ((uint16_t)0x0806)
#define EthernetTypeRARP ((uint16_t)0x8035)
#define EthernetTypeIpv6 ((uint16_t)0x86DD)


struct EthernetHeader
{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;

    void init();
    std::string getDestMAC() const;
    std::string getSrcMAC() const;
    std::string typeToHexStr() const;
    std::string getTypeStr() const;
    uint16_t getType() const;
};

struct ARPHeader
{
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint16_t opcode;
    uint8_t senderMAC[6];
    uint8_t senderIP[4];
    uint8_t targetMAC[6];
    uint8_t targetIP[4];

    void init();
    std::string getHardWareType() const;
    std::string getProtocolType() const;
    std::string getHardWareSize() const;
    std::string getProtocolSize() const;
    std::string getOpcode() const;
    std::string getSenderMAC() const;
    std::string getSenderIP() const;
    std::string getTargetMAC() const;
    std::string getTargetIP() const;

};

#define IPv4DFMask     0x4000 // don't fragment flag
#define IPv4MFMask     0x2000 // more fragments flag
#define IPv4OffsetMask 0x1FFF // fragmenting  bits

struct IPv4Header
{
    uint8_t versionAndHeaderLength;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint8_t sourceIP[4];
    uint8_t destinationIP[4];
    uint8_t options[];

    void init();
    int getVersion() const;
    std::string getVersionStr() const;
    int getHeaderLengthField() const;
    int getHeaderLength() const;
    std::string getHeaderLengthStr() const;
    int getDSCP() const;
    std::string getDSCPStr() const;
    int getECN() const;
    std::string getECNStr() const;
    int getTotalLength() const;
    std::string getTotalLengthStr() const;
    int getIdentification() const;
    std::string getIdentificationStr() const;
    std::string getFlagsStr() const;
    std::string getOffsetStr() const;
    std::string getTTLStr() const;
    std::string getProtocol() const;
    std::string getChecksumStr() const;
    std::string getSourceIPStr() const;
    std::string getDestinationIPStr() const;
    std::string getOptions() const;
};

struct ICMPHeader
{
    uint8_t type;       // ICMP type
    uint8_t code;       // ICMP subtype
    uint16_t checksum;
    uint8_t rest[4];
    uint8_t data[];

    void init();

    std::string getTypeStr() const;
    std::string getCodeStr() const;
    std::string getChecksum() const;
    bool hasIdAndSeq() const;
    std::string getIdentifier() const;
    std::string getSequenceNumber() const;
    std::string getPayload(int len) const;
    std::string getRest() const;
};

struct TCPHeader
{
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  offset;      // header length in 32-bits
    uint8_t  flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
    uint8_t  options[];

    uint16_t getSourcePort() const;
    std::string getSourcePortStr() const;
    uint16_t getDestPort() const;
    std::string getDestPortStr() const;
    uint32_t getSeqNum() const;
    std::string getSeqNumStr() const;
    uint32_t getAckNum() const;
    std::string getAckNumStr() const;
    int getHeaderLengthField() const;
    int getHeaderLength() const;
    std::string getHeaderLengthStr() const;
    std::string getFalgs() const;
    int getWindownSize() const;
    std::string getWindowSizeStr() const;
    int getChecksum() const;
    std::string getChecksumStr() const;
    int getUrgentPointer() const;
    std::string getUrgentPointerStr() const;
    bool hasOptions() const;
    std::string getOptionsStr() const;
};

struct UDPHeader
{
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;

    uint16_t getSourcePort() const;
    std::string getSourcePortStr() const;
    uint16_t getDestPort() const;
    std::string getDestPortStr() const;
    uint16_t getLength() const;
    std::string getLengthStr() const;
    uint16_t getChecksum() const;
    std::string getChecksumStr() const;

};

struct PacketParseResult
{
    PacketParseResult()
      : isARP(false),
        isIPv4(false),
        isIPv6(false),
        isICMP(false),
        isTCP(false),
        isUDP(false)
    { }
    const EthernetHeader* ethernetHeader;
    bool isARP;
    const ARPHeader* arpHeader;
    bool isIPv4;
    const IPv4Header* ipv4Header;
    bool isIPv6;
    bool isICMP;
    const ICMPHeader* icmpHeader;
    bool isTCP;
    const TCPHeader* tcpHeader;
    bool isUDP;
    const UDPHeader* udpHeader;

    size_t getPayloadLength() const
    {
        size_t len = 0;
        if (isTCP)
        {
            len = ipv4Header->getTotalLength() - sizeof(IPv4Header) - tcpHeader->getHeaderLength();
        }
        else if (isUDP)
        {
            len = 0;
        }
        return len;

    }
    const uint8_t* currPtr_;
    const uint8_t* start_;
    size_t len_;
//    std::unique_ptr<IPv6Header> ;
};

class PacketParser
{
public:
    PacketParser(const uint8_t* payload = nullptr, size_t length = 0);
    const PacketParseResult& parse();
private:
    const uint8_t *payload_;
    size_t length_;
    PacketParseResult parseResult_;
};

#endif // PACKETPARSER_H
