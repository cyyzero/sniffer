#include "sniffer.h"
#include "packetparser.h"
#include <QDebug>
#include <string>
#include <thread>

namespace
{

bool defaultFilter()
{
    return true;
}


} // namespace

Sniffer::Sniffer()
  : device_(nullptr),
    start_(false)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    /* Retrieve the device list */
    pcap_if_t *alldevs;
    pcap_if_t *d;
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qFatal("Error in pcap_findalldevs: %s", errbuf);
    }
    for (d = alldevs; d; d = d->next)
    {
        qDebug() << QString("%1 (%2)").arg(d->name, d->description);
        devices_.push_back(d);
    }
    if (devices_.empty())
    {
        qDebug() << "No interfaces found!";
    }
}

Sniffer::~Sniffer()
{
    if (!devices_.empty())
    {
        pcap_freealldevs(devices_[0]);
    }
}

void Sniffer::selectDevice(int index)
{
    assert(index >=0 && index < devices_.size());
    start_ = false;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (device_)
    {
        pcap_close(device_);
    }
    if ((device_ = pcap_open_live(
         devices_[index]->name,	    // name of the device
         65536,                     // portion of the packet to capture.
                                    // 65536 grants that the whole packet will be captured on all the MACs.
         1,                         // promiscuous mode (nonzero means promiscuous)
         1000,                      // read timeout
         errbuf                     // error buffer
         )) == nullptr)
    {
        qFatal("Open device failed, device No. %d, device name: %s", index, devices_[index]->description);
    }
}

int Sniffer::getDeviceNumber() const
{
    return devices_.size();
}

std::vector<const char*> Sniffer::getDeviceNames() const
{
    qDebug() << devices_.size();
    std::vector<const char*> names;

    for (auto device: devices_)
    {
        names.push_back(device->description);
    }
    return names;
}

void Sniffer::start()
{
    start_ = true;
    std::thread worker(&Sniffer::work, this);
    worker.detach();
}

void Sniffer::stop()
{
    if (start_)
        qDebug() << "stop device";
    start_ = false;
}

void Sniffer::work()
{
    qDebug() << "start working...";
    while (true)
    {
        if (!start_)
            return;
        struct pcap_pkthdr* pkt_header;
        const u_char * pkt_data;
        int ret = pcap_next_ex(device_, &pkt_header, &pkt_data);
        if (ret != 1)
        {
            qDebug() << ret;
            qDebug() << pcap_geterr(device_);
            continue;
        }
        PacketParser parser(pkt_data, pkt_header->caplen);
//        qDebug() << "packet len: " << pkt_header->caplen;
        const auto& result = parser.parse();
//        qDebug() << "src:  " << result.ethernetHeader->getSrcMAC().c_str();
//        qDebug() << "dest: " << result.ethernetHeader->getDestMAC().c_str();
//        qDebug() << "type: " << result.ethernetHeader->getType().c_str();
#define output(func) qDebug() << #func << "\t: " << hdr->func().c_str();
//        if (result.isIPv4)
//        {
//            auto hdr = result.ipv4Header;

//            output(getVersionStr);
//            output(getHeaderLengthStr);
//            output(getDSCPStr);
//            output(getECNStr);
//            output(getTotalLengthStr);
//            output(getIdentificationStr);
//            output(getFlagsStr);
//            output(getOffsetStr);
//            output(getTTLStr);
//            output(getProtocol);
//            output(getChecksumStr);
//            output(getSourceIPStr);
//            output(getDestinationIPStr);
//            output(getOptions);
//        }
//        if (result.isICMP)
//        {
//            auto hdr = result.icmpHeader;
//            output(getTypeStr);
//            output(getCodeStr);
//            output(getChecksum);
//            output(getIdentifier)
//            if (hdr->hasIdAndSeq())
//            {
//                output(getIdentifier);
//                output(getSequenceNumber);
//            }
//            else
//            {
//                output(getRest);
//            }
//            int len = result.len_ - (result.currPtr_ - result.start_);
//            qDebug() << "payload: " << "\t: " << result.icmpHeader->getPayload(len).c_str();
//        }
//        if (result.isTCP)
//        {
//            auto hdr = result.tcpHeader;
//            output(getSourcePortStr);
//            output(getDestPortStr);
//            output(getSeqNumStr);
//            output(getAckNumStr);
//            output(getHeaderLengthStr);
//            output(getFalgs);
//            output(getWindowSizeStr);
//            output(getChecksumStr);
//            output(getUrgentPointerStr);
//            output(getOptionsStr);
//            qDebug() << "!!len: " << (result.len_ - (result.currPtr_ - result.start_))
//                     << " " << result.ipv4Header->getTotalLength() - sizeof(IPv4Header) - result.tcpHeader->getHeaderLength();
//        }
        if (result.isUDP)
        {
            auto hdr = result.udpHeader;
            output(getSourcePortStr);
            output(getDestPortStr);
            output(getLengthStr);
            output(getChecksumStr);
            qDebug() << "!!len" << (result.len_ - (result.currPtr_ - result.start_))
                     << hdr->getLength() - sizeof(UDPHeader);
        }
    }
}


