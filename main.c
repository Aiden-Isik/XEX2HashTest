// SEE LINE 99 FOR HOW THE HASHING WORKS

// ------------------------------------------------------------------

// XEX2 Hash Test
// Copyright (c) 2024 Aiden Isik
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// This program makes use of the GNU Nettle library's sha1 hashing.
// Copying conditions and source code link below:
//
// https://git.lysator.liu.se/nettle/nettle/-/blob/master/sha1.h
//
// Copyright (c) 2001, 2012 Niels Möller
//
// This file is part of GNU Nettle.
//
// GNU Nettle is free software: you can redistribute it and/or
// modify it under the terms of either:
//
// * the GNU Lesser General Public License as published by the Free
//  Software Foundation; either version 3 of the License, or (at your
//  option) any later version.
//
// or
//
// * the GNU General Public License as published by the Free
//   Software Foundation; either version 2 of the License, or (at your
//   option) any later version.
//
// or both in parallel, as here.


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <nettle/sha1.h>

#if 'AB' == 0b100000101000010
#define LITTLE_ENDIAN_SYSTEM
#else
#define BIG_ENDIAN_SYSTEM
#endif

#define LITTLE_ENDIAN_FILE false
#define BIG_ENDIAN_FILE true

// XEX2
#define IMAGE_INFO_OFFSET 8
#define IMAGE_INFO_SIZE 0x174

uint32_t get32BitFromFile(FILE *file, bool endianness)
{
  uint8_t store[4];
  fread(store, sizeof(uint8_t), 4, file);
  
  uint32_t result = 0;

  for(int i = 0; i < 4; i++)
    {
      result |= store[i] << i * 8;
    }

  // If system and file endianness don't match we need to change it
#ifdef LITTLE_ENDIAN_SYSTEM
  if(endianness != LITTLE_ENDIAN_FILE)
#else
  if(endianness != BIG_ENDIAN_FILE)
#endif
    {
      switch(endianness)
	{
	case LITTLE_ENDIAN_FILE:
	  result = htonl(result);
	  break;
	case BIG_ENDIAN_FILE:
	  result = ntohl(result);
	  break;
	}
    }

  return result;
}

// How the XEX2 header hashing works:
// 
// It's a SHA1 hash, computed in two parts.
//
// First the data from the end of the image info to the beginning of the PE basefile
// (which is the end of the headers) is hashed. The image info starts 0x8 bytes into
// the security header and runs for 0x174 bytes.
// So security header offset + 0x8 + 0x174 -> basefile offset is the first input to
// the sha1 hash algorithm.
//
// Second, the data from the beginning of the file to the beginning of the image
// info is hashed.
// So 0x0 -> security header offset + 0x8 is the second input to the sha1 algorithm.
//
// Then the final hash can be retrieved with the sha1_digest function.

int main(int argc, char **argv)
{
  FILE *xex = fopen(argv[1], "r");
  
  // Get needed values from XEX
  fseek(xex, 0x10, SEEK_SET);
  uint32_t securityInfoOffset = get32BitFromFile(xex, BIG_ENDIAN_FILE);
  printf("SEC OFFSET: 0x%.8X\n", securityInfoOffset);
  fseek(xex, 0x8, SEEK_SET);
  uint32_t endOfHeaders = get32BitFromFile(xex, BIG_ENDIAN_FILE);
  printf("END OF HEADERS: 0x%.8X\n", endOfHeaders);
  
  uint32_t endOfImageInfo = securityInfoOffset + IMAGE_INFO_OFFSET + IMAGE_INFO_SIZE;
  uint32_t remainderSize = endOfHeaders - endOfImageInfo;

  // Init sha1 hash
  struct sha1_ctx shaContext;
  sha1_init(&shaContext);
  
  // Hash first part (remainder of header is done first, then the start)
  uint8_t remainderOfHeaders[remainderSize];
  fseek(xex, endOfImageInfo, SEEK_SET);

  printf("PART 1 OFFSET START: 0x%.8X\n", ftell(xex));
  
  int remaining = remainderSize;
  
  while(remaining > 0)
    {
      remaining -= fread(remainderOfHeaders + (remainderSize - remaining), sizeof(uint8_t), remaining, xex);
    }

  printf("PART 1 OFFSET END: 0x%.8X\n", ftell(xex));

  sha1_update(&shaContext, remainderSize, remainderOfHeaders);
  
  // Second part (XEX header)
  uint8_t headersStart[securityInfoOffset + IMAGE_INFO_OFFSET];
  fseek(xex, 0, SEEK_SET);

  printf("PART 2 OFFSET START: 0x%.8X\n", ftell(xex));
  
  remaining = securityInfoOffset + IMAGE_INFO_OFFSET;

  while(remaining > 0)
    {
      remaining -= fread(headersStart + ((securityInfoOffset + IMAGE_INFO_OFFSET) - remaining), sizeof(uint8_t), remaining, xex);
    }

  printf("PART 2 OFFSET END: 0x%.8X\n", ftell(xex));
  
  sha1_update(&shaContext, securityInfoOffset + IMAGE_INFO_OFFSET, headersStart);  
  
  // Get final hash
  uint8_t headerHash[20];
  sha1_digest(&shaContext, 20, headerHash);
  
  printf("CALCULATED HASH: 0x");
  
  for(int i = 0; i < 20; i++)
    {
      printf("%.2X", headerHash[i]);
    }

  putchar('\n');
  printf("HASH FROM FILE: 0x");
  fseek(xex, securityInfoOffset + IMAGE_INFO_OFFSET + 0x15C, SEEK_SET);
  fread(headerHash, sizeof(uint8_t), 20, xex);
  
  for(int i = 0; i < 20; i++)
    {
      printf("%.2X", headerHash[i]);
    }

  putchar('\n');
  
  fclose(xex);
  return 0;
}
