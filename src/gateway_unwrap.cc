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

#include "gateway_unwrap.h"
#include "address.h"
#include "wmbus.h"

#include <string.h>

using namespace std;

bool isEmbeddedWMBus(vector<uchar> &data, size_t offset, size_t len) {
  // A valid WMBus telegram needs at least:
  // L(1) + C(1) + M(2) + A(4) + Ver(1) + Type(1) = 10 bytes minimum
  if (len < 10)
    return false;

  uchar l_field = data[offset];
  uchar c_field = data[offset + 1];

  // L-field + 1 should equal the total length of the data
  if ((size_t)(l_field + 1) != len)
    return false;

  // C-field must be a valid WMBus C-field
  // 0x44 = SND_NR (most common), 0x46 = SND_IR
  if (c_field != 0x44 && c_field != 0x46)
    return false;

  return true;
}

// Calculate the number of data bytes for a given DIF lower nibble.
// Returns -1 for variable length (caller must read LVAR byte).
// Returns -2 for special functions (skip to end).
static int difDataLength(uchar dif_lower) {
  switch (dif_lower & 0x0f) {
  case 0x00:
    return 0; // No data
  case 0x01:
    return 1; // 8-bit integer
  case 0x02:
    return 2; // 16-bit integer
  case 0x03:
    return 3; // 24-bit integer
  case 0x04:
    return 4; // 32-bit integer
  case 0x05:
    return 4; // 32-bit real
  case 0x06:
    return 6; // 48-bit integer
  case 0x07:
    return 8; // 64-bit integer
  case 0x08:
    return 0; // Selection for readout
  case 0x09:
    return 1; // 2-digit BCD
  case 0x0A:
    return 2; // 4-digit BCD
  case 0x0B:
    return 3; // 6-digit BCD
  case 0x0C:
    return 4; // 8-digit BCD
  case 0x0D:
    return -1; // Variable length
  case 0x0E:
    return 6; // 12-digit BCD
  case 0x0F:
    return -2; // Special functions
  }
  return -2;
}

// Read a BCD value from data (little-endian BCD) and format as a string.
static string readBCD(vector<uchar> &data, size_t offset, int num_bytes) {
  string result;
  for (int i = num_bytes - 1; i >= 0; i--) {
    if (offset + i >= data.size())
      return "";
    uchar b = data[offset + i];
    result += ('0' + ((b >> 4) & 0x0f));
    result += ('0' + (b & 0x0f));
  }
  return result;
}

// Read an unsigned integer from data (little-endian).
static uint64_t readUint(vector<uchar> &data, size_t offset, int num_bytes) {
  uint64_t val = 0;
  for (int i = num_bytes - 1; i >= 0; i--) {
    if (offset + i >= data.size())
      return 0;
    val = (val << 8) | data[offset + i];
  }
  return val;
}

// Decode a Type I date/time (48-bit, VIF 0x6D) into a human-readable string.
// Byte layout: [sec, min, hour, day|year_lo, month|year_hi, flags]
// This matches the extractDate logic in dvparser.cc.
static string decodeDateTimeTypeI(vector<uchar> &data, size_t offset)
{
    if (offset + 6 > data.size()) return "";

    int sec  = data[offset]     & 0x3f;
    int min  = data[offset + 1] & 0x3f;
    int hour = data[offset + 2] & 0x1f;
    int day  = data[offset + 3] & 0x1f;
    int year_lo = ((data[offset + 3] & 0xe0) >> 5);
    int mon  = data[offset + 4] & 0x0f;
    int year_hi = ((data[offset + 4] & 0xf0) >> 1);

    int year = 2000 + year_lo + year_hi;
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             year, mon, day, hour, min, sec);
    return string(buf);
}

bool tryUnwrapGatewayFrame(vector<uchar> &mbus_frame,
                           vector<vector<uchar>> &wmbus_out,
                           GatewayInfo &meta_out) {
  wmbus_out.clear();
  meta_out = GatewayInfo();

  // An MBus long frame is: 68 LL LL 68 [C] [A] [CI] [data...] [CRC] [16]
  // Minimum size: 4 (header) + 3 (C+A+CI) + 1 (CRC) + 1 (stop) = 9
  if (mbus_frame.size() < 9)
    return false;

  // Verify MBus long frame structure
  size_t pos = 0;
  if (mbus_frame[0] != 0x68 || mbus_frame[3] != 0x68)
    return false;
  if (mbus_frame[1] != mbus_frame[2])
    return false;

  int l_field = mbus_frame[1];
  size_t frame_end = 4 + l_field; // Payload ends here, CRC and 0x16 follow

  if (mbus_frame.size() < frame_end + 2)
    return false;

  // Data payload starts at offset 4
  pos = 4;

  // C-field
  uchar c_field = mbus_frame[pos++];
  (void)c_field;

  // A-field (primary address)
  uchar a_field = mbus_frame[pos++];
  (void)a_field;

  // CI-field — we only handle long header (0x72)
  if (pos >= frame_end)
    return false;
  uchar ci_field = mbus_frame[pos++];
  if (ci_field != 0x72)
    return false;

  // Parse TPL long header:
  // ID (4 bytes, BCD little-endian) + Mfct (2 bytes) + Version (1) + Type (1) +
  // Acc (1) + Status (1) + Config (2)
  if (pos + 12 > frame_end)
    return false;

  // ID field (4 bytes, BCD)
  meta_out.gateway_id = readBCD(mbus_frame, pos, 4);
  pos += 4;

  // Manufacturer (2 bytes, little-endian)
  int mfct = mbus_frame[pos] | (mbus_frame[pos + 1] << 8);
  meta_out.gateway_mfct = manufacturerFlag(mfct);
  pos += 2;

  // Version
  meta_out.gateway_version = mbus_frame[pos++];

  // Type
  meta_out.gateway_type = mbus_frame[pos++];

  // Access number (skip)
  pos++;

  // Status (skip)
  pos++;

  // Configuration (2 bytes, skip)
  pos += 2;

  // Now we're at the start of data records.
  // Walk through data records, classifying each as metadata or embedded WMBus
  // container.

  while (pos < frame_end) {
    // Check for 0x2F filler bytes
    if (mbus_frame[pos] == 0x2f) {
      pos++;
      continue;
    }

    // Read DIF byte
    uchar dif = mbus_frame[pos++];
    if (pos >= frame_end)
      break;

    // Read DIFE chain (bit 7 set means more DIFEs follow)
    int subunit = 0;
    int tariff = 0;
    int storage_nr = (dif & 0x40) ? 1 : 0;
    int dife_count = 0;
    while ((mbus_frame[pos - 1] & 0x80) && pos < frame_end && dife_count < 10) {
      uchar dife = mbus_frame[pos++];
      // Extract subunit from DIFE: bits 6-7 contribute to subunit
      subunit |= ((dife & 0x40) >> 6) << dife_count;
      // Extract tariff from DIFE: bits 4-5
      tariff |= ((dife & 0x30) >> 4) << (dife_count * 2);
      // Extract storage from DIFE: bits 0-3
      storage_nr |= (dife & 0x0f) << (1 + dife_count * 4);
      dife_count++;
      if (!(dife & 0x80))
        break;
    }

    if (pos >= frame_end)
      break;
    (void)tariff;
    (void)storage_nr;

    // Read VIF byte
    uchar vif = mbus_frame[pos++];
    int vif_value = vif & 0x7f;
    bool is_extension_fd = (vif == 0xfd);
    bool is_extension_fb = (vif == 0xfb);

    // Read VIFE chain (bit 7 of VIF/VIFE means more follow)
    vector<uchar> vifes;
    if (vif & 0x80) {
      while (pos < frame_end && vifes.size() < 10) {
        uchar vife = mbus_frame[pos++];
        vifes.push_back(vife);
        if (!(vife & 0x80))
          break;
      }
    }

    if (pos > frame_end)
      break;

    // Determine data length
    int data_len_type = difDataLength(dif);

    if (data_len_type == -2) {
      // Special function — skip to end
      break;
    }

    int data_bytes;
    if (data_len_type == -1) {
      // Variable length — read LVAR byte
      if (pos >= frame_end)
        break;
      uchar lvar = mbus_frame[pos++];
      if (lvar < 0xc0) {
        data_bytes = lvar;
      } else {
        // BCD or type-specific length encoding — not common for containers
        data_bytes = lvar - 0xc0;
      }
    } else {
      data_bytes = data_len_type;
    }

    if (pos + data_bytes > frame_end)
      break;

    size_t data_offset = pos;

    // Check if this variable-length record contains an embedded WMBus telegram
    if (data_len_type == -1 && data_bytes > 0) {
      if (isEmbeddedWMBus(mbus_frame, data_offset, data_bytes)) {
        // Extract the embedded WMBus telegram
        vector<uchar> wmbus_telegram(mbus_frame.begin() + data_offset,
                                     mbus_frame.begin() + data_offset +
                                         data_bytes);
        wmbus_out.push_back(wmbus_telegram);
        pos += data_bytes;
        continue;
      }
    }

    // This is a metadata data record — map to GatewayInfo fields based on VIF

    // VIF 0x78: Fabrication number (8-digit BCD)
    if (!is_extension_fd && !is_extension_fb && vif_value == 0x78 &&
        data_bytes == 4) {
      string fab = readBCD(mbus_frame, data_offset, 4);
      if (subunit == 0 && dife_count == 0) {
        meta_out.gateway_id = fab;
      } else {
        // Subunit > 0 or has DIFE → repeater fabrication number
        meta_out.repeater_id = fab;
      }
    }
    // VIF 0x6D: Date/time Type I (48-bit)
    else if (!is_extension_fd && !is_extension_fb && vif_value == 0x6d &&
             data_bytes == 6) {
      meta_out.datetime = decodeDateTimeTypeI(mbus_frame, data_offset);
    }
    // FD extension VIFEs for RSSI-like values and other metadata
    else if (is_extension_fd && vifes.size() > 0) {
      uchar first_vife = vifes[0] & 0x7f;

      // FD 71: Often used for RSSI or signal-related values (manufacturer
      // specific)
      if (first_vife == 0x71 && data_bytes >= 1) {
        int val = (int)readUint(mbus_frame, data_offset, data_bytes);
        if (subunit == 0 && dife_count == 0) {
          meta_out.rssi = val;
        } else {
          meta_out.repeater_rssi = val;
        }
      }
      // FD F1 94 74: RSSI with extended VIFE chain (Lansen repeater RSSI
      // pattern)
      else if (first_vife == 0x71 && vifes.size() >= 3) {
        // Already handled above for simple case
        // This handles multi-VIFE RSSI with subunit distinction
        int val = (int)readUint(mbus_frame, data_offset, data_bytes);
        if (subunit > 0 || dife_count > 0) {
          meta_out.repeater_rssi = val;
        } else {
          meta_out.rssi = val;
        }
      }
      // FD 0F: Software version
      else if (first_vife == 0x0f && data_bytes >= 1) {
        uint64_t val = readUint(mbus_frame, data_offset, data_bytes);
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d", (int)val);
        meta_out.extra_fields["software_version"] = string(buf);
      }
      // Other FD extensions → store as extra field
      else {
        uint64_t val = readUint(mbus_frame, data_offset, data_bytes);
        char key[64];
        snprintf(key, sizeof(key), "fd_%02x", first_vife);
        if (subunit > 0 || dife_count > 0) {
          snprintf(key, sizeof(key), "fd_%02x_su%d", first_vife, subunit);
        }
        char valbuf[32];
        snprintf(valbuf, sizeof(valbuf), "%llu", (unsigned long long)val);
        meta_out.extra_fields[string(key)] = string(valbuf);
      }
    }
    // Other VIFs → store as extra field with auto-generated name
    else if (data_bytes > 0 && data_bytes <= 8) {
      uint64_t val = readUint(mbus_frame, data_offset, data_bytes);
      char key[64];
      snprintf(key, sizeof(key), "vif_%02x", vif_value);
      if (subunit > 0 || dife_count > 0) {
        snprintf(key, sizeof(key), "vif_%02x_su%d", vif_value, subunit);
      }
      char valbuf[32];
      snprintf(valbuf, sizeof(valbuf), "%llu", (unsigned long long)val);
      meta_out.extra_fields[string(key)] = string(valbuf);
    }

    pos += data_bytes;
  }

  if (wmbus_out.size() > 0) {
    meta_out.present = true;
    return true;
  }

  return false;
}
