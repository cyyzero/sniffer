#include "packetparser.h"
#include "utility.h"
#include <qendian.h>
#include <QDebug>

PacketParser::PacketParser(const uint8_t* payload, size_t length)
  : payload_(payload),
    length_(length)
{
}

const std::shared_ptr<PacketParseResult>& PacketParser::parse()
{
//    qDebug() << "parse...";
    if (parseResult_ && payload_ == parseResult_->start_)
        return parseResult_;
    parseResult_ = std::make_shared<PacketParseResult>(payload_, length_);
//    qDebug() << (void*) payload_ << " " << (void*)parseResult_->start_;
    payload_ = parseResult_->start_;
    auto ptr = payload_;
    parseResult_->ethernetHeader = (const EthernetHeader*)payload_;
    ptr += sizeof (EthernetHeader);
    switch (parseResult_->ethernetHeader->getType())
    {
    case EthernetTypeARP:
        parseResult_->isARP = true;
        parseResult_->arpHeader = (const ARPHeader*)ptr;
        parseResult_->currPtr_ = ptr + sizeof (ARPHeader);
        return parseResult_;
    case EthernetTypeIPv4:
        parseResult_->isIPv4 = true;
        parseResult_->ipv4Header = (const IPv4Header*)ptr;
        ptr += parseResult_->ipv4Header->getHeaderLength();
        parseResult_->currPtr_ = ptr;
        break;
    case EthernetTypeIpv6:
        parseResult_->isIPv6 = true;
        parseResult_->currPtr_ = ptr;
        return parseResult_;
    default:
        parseResult_->currPtr_ = ptr;
        return parseResult_;
    }
    switch (parseResult_->ipv4Header->protocol)
    {
    case 0x01: // ICMP
    {
        parseResult_->isICMP = true;
        parseResult_->icmpHeader = (const ICMPHeader*)ptr;
        parseResult_->currPtr_ = ptr + sizeof(ICMPHeader);
        return parseResult_;
    }
    case 0x06: // tcp
        parseResult_->isTCP = true;
        parseResult_->tcpHeader = (const TCPHeader*)ptr;
        ptr += parseResult_->tcpHeader->getHeaderLength();
        parseResult_->currPtr_ = ptr;
        break;
    case 0x11: // udp
        parseResult_->isUDP = true;
        parseResult_->udpHeader = (const UDPHeader*)ptr;
        ptr += sizeof(UDPHeader);
        parseResult_->currPtr_ = ptr;
        break;
    case 0x02: // igmp
//        break;
    default:
        parseResult_->currPtr_ = ptr;
        return parseResult_;
    }
    size_t dataLen = parseResult_->getPayloadLength();
    if (parseResult_->isTCP && dataLen > 10)
    {
        auto sourcePort = parseResult_->tcpHeader->getSourcePort();
        auto destPort = parseResult_->tcpHeader->getDestPort();
        if (sourcePort == 80 || destPort == 80)
        {
            const char*str = (const char*)ptr;
            if (start_with(str, "HTTP/") ||
                start_with(str, "GET") ||
                start_with(str, "HEAD") ||
                start_with(str, "POST") ||
                start_with(str, "PUT") ||
                start_with(str, "DELETE") ||
                start_with(str, "CONNECT") ||
                start_with(str, "OPTIONS") ||
                start_with(str, "TRACE") ||
                start_with(str, "PATCH"))
            {
                parseResult_->isHTTP = true;
                parseResult_->httpHeader = new HTTPHeader(str, dataLen);
            }
        }
        else if ((sourcePort == 443 || destPort == 443) &&
                 dataLen > sizeof(TLSHeader)
                 )
        {
            parseResult_->tlsHeader = (const TLSHeader*)ptr;
            auto header = parseResult_->tlsHeader;
            if (header->isKnownType() && header->isKnownVersion())
            {
                parseResult_->isTLS = true;
            }
        }
    }

    return parseResult_;
}

std::string EthernetHeader::getDestMAC() const
{
    return MACToStr(dest);
}

std::string EthernetHeader::getSrcMAC() const
{
    return MACToStr(src);
}

std::string EthernetHeader::typeToHexStr() const
{
    char buf[8];
    snprintf(buf, 8, "%0x", netToHost(type));
    return std::string("0x").append(buf);
}

std::string EthernetHeader::getTypeStr() const
{
    auto t= netToHost(type);
    switch (t)
    {
    case EthernetTypeIPv4:
        return "IPv4 0x0800";
    case EthernetTypeIpv6:
        return "IPv6 0x86dd";
    case EthernetTypeARP:
        return "ARP 0x0806";
    case EthernetTypeRARP:
        return "RARP 0x8035";
    default:
        return std::string("unknown ").append(to_hex_string(t));
    }
}

uint16_t EthernetHeader::getType() const
{
    return netToHost(type);
}

std::string ARPHeader::getHardWareType() const
{
    switch (netToHost(hardwareType))
    {
    case 1:
        return "Ethernet (1)";
    default:
        return "unknown";
    }
}

std::string ARPHeader::getProtocolType() const
{
    switch (netToHost(protocolType))
    {
    case 0x0800:
        return "IPv4 (0x0800)";
    default:
        return "unknown";
    }
}

std::string ARPHeader::getHardWareSize() const
{
    return std::to_string(hardwareSize);
}

std::string ARPHeader::getProtocolSize() const
{
    return std::to_string(protocolSize);
}

std::string ARPHeader::getOpcode() const
{
    auto op = netToHost(opcode);
    switch (op)
    {
    case 1:
        return "request (1)";
    case 2:
        return "response (2)";
    default:
        return std::to_string(op);
    }
}

std::string ARPHeader::getSenderMAC() const
{
    return MACToStr(senderMAC);
}

std::string ARPHeader::getSenderIP() const
{
    return IPToStr(senderIP);
}

std::string ARPHeader::getTargetMAC() const
{
    return MACToStr(targetMAC);
}

std::string ARPHeader::getTargetIP() const
{
    return IPToStr(targetIP);
}

int IPv4Header::getVersion() const
{
    return (0xf0 & versionAndHeaderLength) >> 4;
}

std::string IPv4Header::getVersionStr() const
{
    return std::to_string(getVersion());
}

int IPv4Header::getHeaderLengthField() const
{
    return 0xf & versionAndHeaderLength;
}

int IPv4Header::getHeaderLength() const
{
    return 4 * getHeaderLengthField();
}

std::string IPv4Header::getHeaderLengthStr() const
{
    char buf[24];
    snprintf(buf, 24, "%d bytes (%d)", getHeaderLength(), getHeaderLengthField());
    return buf;
}

int IPv4Header::getDSCP() const
{
    return (0xfc & tos) >> 2;
}

std::string IPv4Header::getDSCPStr() const
{
    return std::to_string(getDSCP());
}

int IPv4Header::getECN() const
{
    return 0x3 & tos;
}

std::string IPv4Header::getECNStr() const
{
    return std::to_string(getECN());
}

int IPv4Header::getTotalLength() const
{
    return netToHost(totalLength);
}

std::string IPv4Header::getTotalLengthStr() const
{
    return std::to_string(getTotalLength());
}

int IPv4Header::getIdentification() const
{
    return netToHost(identification);
}

std::string IPv4Header::getIdentificationStr() const
{
    char buf[64];
    snprintf(buf, 64, "0x%x (%d)", getIdentification(), getIdentification());
    return buf;
}

std::string IPv4Header::getFlagsStr() const
{
    auto fo = netToHost(flagsAndOffset);
    std::string flag("000");
    if (IPv4DFMask & fo)
    {
        flag[1] = '1';
    }
    if (IPv4MFMask & fo)
    {
        flag[2] = '1';
    }

    if (IPv4DFMask & fo)
    {
        flag.append(" DF");
    }
    if (IPv4MFMask & fo)
    {
        flag.append(" MF");
    }
    return flag;
}

std::string IPv4Header::getOffsetStr() const
{
    return std::to_string(IPv4OffsetMask & netToHost(flagsAndOffset));
}

std::string IPv4Header::getTTLStr() const
{
    return std::to_string(timeToLive);
}

std::string IPv4Header::getProtocol() const
{
    switch (protocol)
    {
    case 0x01:
        return "ICMP (1)";
    case 0x02:
        return "IGMP (2)";
    case 0x06:
        return "TCP (6)";
    case 0x11:
        return "UDP (11)";
    default:
        return std::to_string(protocol);
    }
}

std::string IPv4Header::getChecksumStr() const
{
    return std::string("0x").append(to_hex_string(netToHost(headerChecksum)));
}

std::string IPv4Header::getSourceIPStr() const
{
    return IPToStr(sourceIP);
}

std::string IPv4Header::getDestinationIPStr() const
{
    return IPToStr(destinationIP);
}

std::string IPv4Header::getOptions() const
{
    int optionSize = getHeaderLength() - sizeof(IPv4Header);
    return to_hex_string(options, optionSize);
}

std::string ICMPHeader::getTypeStr() const
{
    switch (type)
    {
    case 0:
        return "0 (Echo (ping) reply)";
    case 8:
        return "8 (Echo (ping) request)";
    case 3:
        return "3 (Destination Unreachable)";
    default:
        return std::to_string(type);
    }
}

std::string ICMPHeader::getCodeStr() const
{
    return std::to_string(code);
}

std::string ICMPHeader::getChecksum() const
{
    return std::string("0x").append(to_hex_string(netToHost(checksum)));
}

bool ICMPHeader::hasIdAndSeq() const
{
    return type == 0 || type == 8 || type == 13 || type == 14 ||
           type == 17|| type == 18;
}

std::string ICMPHeader::getIdentifier() const
{
    uint16_t identifier = *((uint16_t*)rest);
    identifier = netToHost(identifier);
    char buf[24];
    snprintf(buf, 24, "%d (0x%04x)", identifier, identifier);
    return buf;
}

std::string ICMPHeader::getSequenceNumber() const
{
    uint16_t seqNum = *((uint16_t*)rest+2);
    seqNum = netToHost(seqNum);
    char buf[24];
    snprintf(buf, 24, "%d (0x%04x)", seqNum, seqNum);
    return buf;
}

std::string ICMPHeader::getPayload(int len) const
{
    return to_hex_string(data, len);
}

std::string ICMPHeader::getRest() const
{
    return to_hex_string(rest, 4);
}

uint16_t TCPHeader::getSourcePort() const
{
    return netToHost(sourcePort);
}

std::string TCPHeader::getSourcePortStr() const
{
    return std::to_string(getSourcePort());
}

uint16_t TCPHeader::getDestPort() const
{
    return netToHost(destPort);
}

std::string TCPHeader::getDestPortStr() const
{
    return std::to_string(getDestPort());
}

uint32_t TCPHeader::getSeqNum() const
{
    return netToHost(seqNum);
}

std::string TCPHeader::getSeqNumStr() const
{
    return std::to_string(getSeqNum());
}

uint32_t TCPHeader::getAckNum() const
{
    return netToHost(ackNum);
}

std::string TCPHeader::getAckNumStr() const
{
    return std::to_string(getAckNum());
}

int TCPHeader::getHeaderLengthField() const
{
    return (offset & 0xf0) >> 4;
}

int TCPHeader::getHeaderLength() const
{
    return 4 * getHeaderLengthField();
}

std::string TCPHeader::getHeaderLengthStr() const
{
    return std::to_string(getHeaderLength());
}

std::string TCPHeader::getFalgs() const
{
    std::string ret("0x");
    char buf[16];
    snprintf(buf, 16,"%01x", offset & 0x0f);
    ret.append(buf);
    snprintf(buf, 16, "%02x", flags);
    ret.append(buf);
    if (offset & 0x1)
    {
        ret.append(" Nonce");
    }
    if (flags & 0x80)
    {
        ret.append(" CWR");
    }
    if (flags & 0x40)
    {
        ret.append(" ECN-Echo");
    }
    if (flags & 0x20)
    {
        ret.append(" Urgent");
    }
    if (flags & 0x10)
    {
        ret.append(" ACK");
    }
    if (flags & 0x8)
    {
        ret.append(" Push");
    }
    if (flags & 0x4)
    {
        ret.append(" Reset");
    }
    if (flags& 0x2)
    {
        ret.append(" SYN");
    }
    if (flags & 0x1)
    {
        ret.append(" FIN");
    }
    return ret;
}

int TCPHeader::getWindownSize() const
{
    return netToHost(windowSize);
}

std::string TCPHeader::getWindowSizeStr() const
{
    return std::to_string(getWindownSize());
}

int TCPHeader::getChecksum() const
{
    return netToHost(checksum);
}

std::string TCPHeader::getChecksumStr() const
{
    return std::string("0x").append(to_hex_string(getChecksum()));
}

int TCPHeader::getUrgentPointer() const
{
    return netToHost(urgentPointer);
}

std::string TCPHeader::getUrgentPointerStr() const
{
    return std::to_string(getUrgentPointer());
}

bool TCPHeader::hasOptions() const
{
    return getHeaderLength() > (int)sizeof(TCPHeader);
}

std::string TCPHeader::getOptionsStr() const
{
    std::string ret;
    if (!hasOptions())
    {
        return ret;
    }
    int len = getHeaderLength() - 20;
    int idx = 0;
    while (idx < len)
    {
        switch (options[idx])
        {
        case 0:
            ret.append(" EOL");
            idx = len;
            break;
        case 1:
            ret.append(" NOP");
            ++idx;
            break;
        case 2:
        {
            ret.append(" MSS(");
            if (++idx >= len)
                break;
            if (++idx >= len)
                break;
            uint16_t n = *((uint16_t*)(options + idx));
            idx += 2;
            n = netToHost(n);
            ret.append(std::to_string(n));
            ret.push_back(')');
            break;
        }
        case 3:
        {
            if (++idx >= len)
                break;
            ret.append(" WindowScale(");
            if (++idx >= len)
                break;
            ret.append(std::to_string((uint32_t)options[idx]));
            ++idx;
            ret.push_back(')');
            break;
        }
        case 4:
        {
            ret.append(" AllowSACK");
            idx += 2;
            break;
        }
        case 5:
        {
            if (++idx >= len)
                break;
            int optLen = options[idx] - 2;
            if (++idx >= len)
                break;
            ret.append(" sack(");
            while (optLen >= 0 && idx < len)
            {
                uint32_t ackN = *((uint32_t*)(options + idx));
                ackN = netToHost(ackN);
                idx += 4;
                optLen -= 4;
                ret.append(std::to_string(ackN));
                ret.push_back(' ');
            }
            ret.push_back(')');
            break;
        }
        default:
        {
            ret.append(" kind").append(std::to_string((uint32_t)options[idx]));
            if (++idx >= len)
                break;
            int optLen = options[idx] - 2;
            if (++idx >= len)
                break;
            if (idx + optLen >= len)
                break;
            ret.append("(0x").append(to_hex_string(idx + options, optLen));
            ret.push_back(')');
            idx += optLen;
            break;
        }
        }
    }
    return ret;
}

uint16_t UDPHeader::getSourcePort() const
{
    return netToHost(sourcePort);
}

std::string UDPHeader::getSourcePortStr() const
{
    return std::to_string(getSourcePort());
}

uint16_t UDPHeader::getDestPort() const
{
    return netToHost(destPort);
}

std::string UDPHeader::getDestPortStr() const
{
    return std::to_string(getDestPort());
}

uint16_t UDPHeader::getLength() const
{
    return netToHost(length);
}

std::string UDPHeader::getLengthStr() const
{
    return std::to_string(getLength());
}

uint16_t UDPHeader::getChecksum() const
{
    return netToHost(checksum);
}

std::string UDPHeader::getChecksumStr() const
{
    return std::to_string(getChecksum());
}

HTTPHeader::HTTPHeader(const char *start, size_t len)
    : start_(start),
      len_(len)
{
    const char* left = start_, *right = start_ + 1;
    while (right < len_ + start_)
    {
        if (*right == '\r')
        {
            if (right + 4 > len_ + start_)
            {
                data_ = start_ + len;
                break;
            }
            if (start_with(right, "\r\n\r\n"))
            {
                headers_.emplace_back(left, right - left);
                data_ = right + 4;
                break;
            }
            else if (start_with(right, "\r\n"))
            {
                headers_.emplace_back(left, right - left);
                left = right + 2;
                right = left + 1;
            }
        }
        ++right;
    }

    if (data_ >= len_ + start_)
        return;
    bool retHex = false;
    auto dataLen = len_ - (data_ - start_);
    size_t checkNum = dataLen < 4 ? dataLen : 4;
    for (size_t i = 0; i < checkNum; ++i)
    {
        if (!isprint(data_[i]))
        {
            retHex = true;
            break;
        }
    }
    if (retHex)
    {
        std::string hexStr = to_hex_string((const uint8_t*)data_, dataLen);
        if (dataLen >= 20)
        {
            hexStr = hexStr.substr(0, 20);
        }
        hexStr.append(("..."));
        body_ = hexStr;
    }
    else
        body_ = std::string(data_, dataLen);
}

std::vector<std::string> HTTPHeader::getHeaderLines() const
{
    return headers_;
}

std::string HTTPHeader::getBody() const
{
    return body_;
}

bool TLSHeader::isKnownType() const
{
    return type == 0x14 ||
            type == 0x15 ||
            type == 0x16 ||
            type == 0x17 ||
            type == 0x18;
}

bool TLSHeader::isKnownVersion() const
{
    return version[0] == 3 &&
            (version[1] >= 0 && version[1] <= 4);
}

int TLSHeader::getType() const
{
    return type;
}

std::string TLSHeader::getTypeStr() const
{
    switch (type)
    {
    case 0x14: 	 // 20 	ChangeCipherSpec
        return "ChangeCipherSpec";
        break;
    case 0x15: 	 // 21 	Alert
        return "Alert";
        break;
    case 0x16: 	 // 22 	Handshake
        return "Handshake";
        break;
    case 0x17: 	 // 23 	Application
        return "ApplicationData";
        break;
    case 0x18: 	 // 24 	Heartbeat
        return "Heartbeat";
        break;
    default:
        return "Unknown";
    }
}

std::string TLSHeader::getVersionStr() const
{
    if (version[0] != 3)
        return std::string();
    switch (version[1])
    {
    case 0:
        return "SSL3.0";
    case 1:
        return "TLS1.0";
    case 2:
        return "TLS1.1";
    case 3:
        return "TLS1.2";
    case 4:
        return "TLS1.3";
    default:
        return "unknown";
    }

}

uint16_t TLSHeader::getLength() const
{
    qDebug() << "length: 0x" << to_hex_string(length).c_str();
    return length;
}

std::string TLSHeader::getLengthStr() const
{
//    qDebug() << netToHost(getLength());
    return std::to_string(getLength());
}
