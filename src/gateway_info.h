/*
 Copyright (C) 2026 Azeezulla Khan (gpl-3.0-or-later)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef GATEWAY_INFO_H
#define GATEWAY_INFO_H

#include <map>
#include <string>

struct GatewayInfo {
  bool present = false; // True if this telegram came through a gateway

  // Gateway identity (from MBus TPL long header)
  std::string gateway_id;   // Fabrication number or TPL ID
  std::string gateway_mfct; // Manufacturer flag (e.g., "LAS")
  int gateway_version = 0;
  int gateway_type = 0;

  // Metadata from gateway data records
  std::string datetime; // Timestamp when gateway received the packet
  int rssi = -1;        // RSSI of the received packet (-1 = not available)

  // Repeater info (if packet was relayed)
  std::string repeater_id; // Repeater serial number ("" = not via repeater)
  int repeater_rssi = -1;  // Repeater RSSI (-1 = not available)

  // Any additional metadata fields (auto-named from VIF)
  std::map<std::string, std::string> extra_fields;
};

#endif
