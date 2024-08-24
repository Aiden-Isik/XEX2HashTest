XEX2 Hash Test

Copyright (c) 2024 Aiden Isik

This is a test program made during the planning of the FreeChainXenon
project, a fully free/libre homebrew toolchain for the Xbox 360. It
takes an XEX2 file path as it's only parameter and outputs the header
hash found in the XEX file, as well as the calculated header hash.

I have decided to publish this with well-commented code as a resource
for anyone in the future who might want to understand how the hashing is done.

The program does not check for file validity and has no actual checks for
failures. It is expected you give it a valid XEX2 file.

Prerequisites:
 - GNU Nettle library (on Debian: sudo apt install nettle-dev)
 - GCC (on Debian: sudo apt install build-essential)

To compile: gcc main.c -o xex2hashtest -lnettle

-----

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

-----

This program makes use of the GNU Nettle library's sha1 hashing.
Copying conditions and source code link below:

https://git.lysator.liu.se/nettle/nettle/-/blob/master/sha1.h

Copyright (c) 2001, 2012 Niels Möller

This file is part of GNU Nettle.

GNU Nettle is free software: you can redistribute it and/or
modify it under the terms of either:

* the GNU Lesser General Public License as published by the Free
 Software Foundation; either version 3 of the License, or (at your
 option) any later version.

or

* the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your
  option) any later version.

or both in parallel, as here.
