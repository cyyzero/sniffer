#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <vector>
#include <atomic>
#include <memory>
#include <functional>
#include <mutex>
#include <condition_variable>

class PacketParseResult;
class Sniffer
{
public:
    using callback_t = std::function<void(const std::shared_ptr<PacketParseResult>&)>;
    Sniffer();
    ~Sniffer();

    int getDeviceNumber() const;
    std::vector<const char*> getDeviceNames() const;

    void selectDevice(int index);
    void start();
    void stop();     //synchornized

    void setParsedCallback(callback_t func);

private:

    void work();
    int deviceIndex_;
    std::atomic_bool start_;
    std::vector<pcap_if_t *> devices_;
    callback_t callback_;
    std::condition_variable cv_;
    std::mutex m_;
};

#endif // SNIFFER_H
