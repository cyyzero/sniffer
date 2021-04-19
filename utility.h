#ifndef UTILITY_H
#define UTILITY_H

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <type_traits>

// only works for big-endian architecture
uint16_t hostToNet(uint16_t);
uint16_t netToHost(uint16_t);

uint32_t hostToNet(uint32_t);
uint32_t netToHost(uint32_t);

uint64_t hostToNet(uint64_t);
uint64_t netToHost(uint64_t);

std::string to_hex_string(const uint8_t* n, size_t len);
std::string MACToStr(const uint8_t* addr);
std::string IPToStr(uint32_t addr);
std::string IPToStr(const uint8_t* addr);

uint8_t exchangeHalfByte(uint8_t n);

template<typename T>
std::string to_hex_string(T n)
{
    static_assert(std::is_integral<T>::value, "T should be integeral type");
    std::stringstream stream;
    stream << std::setfill ('0') << std::setw(sizeof(T)*2) << std::hex;

    // If T is an 8-bit integer type (e.g. uint8_t or int8_t) it will be
    // treated as an ASCII code, giving the wrong result. So we use C++17's
    // "if constexpr" to have the compiler decides at compile-time if it's
    // converting an 8-bit int or not.
    if constexpr (std::is_same<std::uint8_t, T>::value)
    {
        // Unsigned 8-bit unsigned int type. Cast to int (thanks Lincoln) to
        // avoid ASCII code interpretation of the int. The number of hex digits
        // in the  returned string will still be two, which is correct for 8 bits,
        // because of the 'sizeof(T)' above.
        stream << static_cast<int>(n);
    }
    else if (std::is_same<std::int8_t, T>::value)
    {
        // For 8-bit signed int, same as above, except we must first cast to unsigned
        // int, because values above 127d (0x7f) in the int will cause further issues.
        // if we cast directly to int.
        stream << static_cast<int>(static_cast<uint8_t>(n));
    }
    else
    {
        // No cast needed for ints wider than 8 bits.
        stream << n;
    }

    return stream.str();
}


#endif // UTILITY_H
