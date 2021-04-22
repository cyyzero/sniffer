#include "sniffer.h"
#include "packetparser.h"
#include <QDebug>
#include <string>
#include <thread>
#include <chrono>

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
    assert(index >=0 && index < (int)devices_.size());
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
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lk(m_);
    if (start_)
        qDebug() << "stop device";
    start_ = false;
    cv_.wait_for(lk, 1s);
}

void Sniffer::setParsedCallback(Sniffer::callback_t func)
{
    callback_ = std::move(func);
}

void Sniffer::work()
{
    qDebug() << "start working...";
    while (true)
    {
        if (!start_)
            break;
        struct pcap_pkthdr* pkt_header;
        const u_char * pkt_data;
        int ret = pcap_next_ex(device_, &pkt_header, &pkt_data);
        if (ret != 1 || pkt_header->caplen != pkt_header->len)
        {
            qDebug() << ret;
            qDebug() << pcap_geterr(device_);
            continue;
        }
        PacketParser parser(pkt_data, pkt_header->caplen);
        std::shared_ptr<PacketParseResult> result = parser.parse();
        if (callback_)
        {
            callback_(result );
        }
    }
    cv_.notify_one();
}


