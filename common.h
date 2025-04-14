#pragma once

#include <Windows.h>
#include <iostream>
#include <sstream>

inline DWORD loadInt(const std::string& str, bool as_hex)
{
    DWORD intVal = 0;

    std::stringstream ss;
    ss << (as_hex ? std::hex : std::dec) << str;
    ss >> intVal;
    return intVal;
}

inline std::string writeInt(ULONGLONG val, bool as_hex)
{
    std::stringstream ss;
    ss << (as_hex ? std::hex : std::dec) << val;
    return ss.str();
}
