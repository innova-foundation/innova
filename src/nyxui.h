#ifndef INNOVA_NYXUI_H
#define INNOVA_NYXUI_H

#include <stdint.h>
#include <string>

// Stable 0..359 hue for an address avatar.
int NyxAvatarHue(const std::string& address);

// Up to two uppercase initials; for a bare address, two characters after the prefix.
std::string NyxInitials(const std::string& name, const std::string& address);

// "iABCDE…WXYZ12" short form; short strings are returned unchanged.
std::string NyxShortAddress(const std::string& address);

// Nickname, then address-book label, then short address.
std::string NyxDisplayName(const std::string& address, const std::string& nickname,
                           const std::string& bookLabel);

static const int64_t NYX_GROUP_WINDOW_SECS = 5 * 60;

// True when a message continues the previous row's group: same sender, same day,
// not earlier and within the window.
bool NyxGroupsWith(const std::string& prevSender, int64_t prevTime, int prevDay,
                   const std::string& sender, int64_t time, int day);

#endif
