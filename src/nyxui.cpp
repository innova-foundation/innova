#include "nyxui.h"

#include <cctype>

int NyxAvatarHue(const std::string& address)
{
    uint32_t h = 2166136261u;
    for (unsigned char c : address)
    {
        h ^= c;
        h *= 16777619u;
    }
    return (int)(h % 360);
}

static size_t Utf8Len(const std::string& s, size_t i)
{
    unsigned char c = s[i];
    size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 1;
    return i + n <= s.size() ? n : s.size() - i;
}

static std::string Upper(const std::string& s)
{
    std::string r = s;
    if (r.size() == 1)
        r[0] = (char)std::toupper((unsigned char)r[0]);
    return r;
}

std::string NyxInitials(const std::string& name, const std::string& address)
{
    if (!name.empty() && name != address && name.find("\xE2\x80\xA6") == std::string::npos)
    {
        std::string out;
        bool fStart = true;
        for (size_t i = 0; i < name.size() && out.size() < 8;)
        {
            size_t n = Utf8Len(name, i);
            bool fSpace = n == 1 && std::isspace((unsigned char)name[i]);
            if (fSpace)
                fStart = true;
            else if (fStart)
            {
                out += Upper(name.substr(i, n));
                fStart = false;
                if (out.size() >= 2 && (unsigned char)out[0] < 0x80)
                    break;
                if ((unsigned char)out[0] >= 0x80)
                    break;
            }
            i += n;
        }
        if (!out.empty())
            return out;
    }
    if (address.size() >= 3)
        return Upper(address.substr(1, 1)) + Upper(address.substr(2, 1));
    return "?";
}

std::string NyxShortAddress(const std::string& address)
{
    if (address.size() <= 20)
        return address;
    return address.substr(0, 12) + "\xE2\x80\xA6" + address.substr(address.size() - 6);
}

std::string NyxDisplayName(const std::string& address, const std::string& nickname,
                           const std::string& bookLabel)
{
    if (!nickname.empty())
        return nickname;
    if (!bookLabel.empty())
        return bookLabel;
    return NyxShortAddress(address);
}

bool NyxGroupsWith(const std::string& prevSender, int64_t prevTime, int prevDay,
                   const std::string& sender, int64_t time, int day)
{
    if (prevSender.empty() || prevSender != sender || prevDay != day)
        return false;
    int64_t d = time - prevTime;
    return d >= 0 && d <= NYX_GROUP_WINDOW_SECS;
}
