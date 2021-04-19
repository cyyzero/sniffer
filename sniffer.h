#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <vector>
#include <atomic>


class Sniffer
{
public:
    Sniffer();
    ~Sniffer();

    int getDeviceNumber() const;
    std::vector<const char*> getDeviceNames() const;

    void selectDevice(int index);
    void start();
    void stop();

private:
    void work();
    pcap_t *device_;
    std::atomic_bool start_;
    std::vector<pcap_if_t *> devices_;
};

#endif // SNIFFER_H
