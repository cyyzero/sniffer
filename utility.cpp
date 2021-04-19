#include "utility.h"

namespace
{
uint16_t reverse(uint16_t n)
{
    return ((n & 0xff) << 8) |
           ((n & 0xff00) >> 8);
}

uint32_t reverse(uint32_t n)
{
    return ((n & 0xff) << 3*8)   |
           ((n & 0xff00) << 8)   |
           ((n & 0xff0000) >> 8) |
           ((n & 0xff000000) >> 3*8);
}

uint64_t reverse(uint64_t n)
{
    return ((n & 0xff) << 7*8) |
           ((n & 0xff00) << 5*8) |
           ((n & 0xff0000) << 3*8) |
           ((n & 0xff000000) << 8) |
           ((n & 0xff00000000) >> 8) |
           ((n & 0xff0000000000) >> 3*8) |
           ((n & 0xff000000000000) >> 5*8) |
           ((n & 0xff00000000000000) >> 7*8);
}

}

uint16_t hostToNet(uint16_t n)
{
    return reverse(n);
}

uint16_t netToHost(uint16_t n)
{
    return reverse(n);
}

uint32_t hostToNet(uint32_t n)
{
    return reverse(n);
}

uint32_t netToHost(uint32_t n)
{
    return reverse(n);
}

uint64_t hostToNet(uint64_t n)
{
    return reverse(n);
}

uint64_t netToHost(uint64_t n)
{
    return reverse(n);
}

std::string to_hex_string(const uint8_t* p, size_t len)
{
    std::string ret;
    char buf[8];
    for (size_t i = 0; i < len; ++i)
    {
        snprintf(buf, 8, "%02x", p[i]);
        ret.append(buf);
    }
    return ret;
}

std::string MACToStr(const uint8_t* addr)
{
    std::string ret;
    char buf[8];
    for (int i = 0; i < 6; ++i)
    {
        snprintf(buf, 8, "%02x", addr[i]);
        ret.append(buf).push_back(':');
    }
    ret.pop_back();
    return ret;
}

std::string IPToStr(uint32_t addr)
{
    return IPToStr(reinterpret_cast<uint8_t*>(&addr));
}

std::string IPToStr(const uint8_t* addr)
{
    std::string ret;
    char buf[8];
    for (int i = 0; i < 4; ++i)
    {
        snprintf(buf, 8, "%d", addr[i]);
        ret.append(buf).push_back('.');
    }
    ret.pop_back();
    return ret;
}


uint8_t exchangeHalfByte(uint8_t n)
{
    return ((n & 0xf) << 4) | ((n & 0xf0) >> 4);
}
