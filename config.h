#pragma once

// CityHash has no special config on Windows.
// These defines prevent missing symbols.

#define HAVE_BUILTIN_EXPECT 0
#define HAVE_UNALIGNED_ACCESS 1
#define HAVE_ENDIAN_H 0
#define HAVE_BYTESWAP_H 0