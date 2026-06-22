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

#ifndef GATEWAY_UNWRAP_H
#define GATEWAY_UNWRAP_H

#include "gateway_info.h"
#include "util.h"

#include <vector>

// Check if a byte sequence looks like a valid WMBus telegram.
// Validates L-field consistency and C-field validity.
bool isEmbeddedWMBus(std::vector<uchar> &data, size_t offset, size_t len);

// Attempt to unwrap a gateway MBus frame containing embedded WMBus telegram(s).
// Input:  mbus_frame — the full MBus frame (starting with 68 LL LL 68)
// Output: wmbus_out  — vector of extracted WMBus telegram byte vectors
//         meta_out   — gateway metadata (id, timestamp, rssi, repeater info)
// Returns true if at least one embedded WMBus telegram was found and extracted.
// Returns false if the frame is a normal MBus telegram (no embedded WMBus),
// in which case the frame should be processed normally.
bool tryUnwrapGatewayFrame(std::vector<uchar> &mbus_frame,
                           std::vector<std::vector<uchar>> &wmbus_out,
                           GatewayInfo &meta_out);

#endif
