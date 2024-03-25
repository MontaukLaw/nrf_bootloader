
/* This file was automatically generated by nrfutil on 2021-08-21 (YY-MM-DD) at 13:01:46 */

#include "stdint.h"
#include "compiler_abstraction.h"

/* This file was generated with a throwaway private key, that is only inteded for a debug version of the DFU project.
  Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate a valid public key. */

#ifdef NRF_DFU_DEBUG_VERSION 

/** @brief Public key used to verify DFU images */

/** @brief Public key used to verify DFU images */
__ALIGN(4) const uint8_t pk[64] =
{
    0x52, 0xa8, 0xa7, 0x61, 0x8b, 0x4c, 0xeb, 0x44, 0x40, 0x02, 0xc3, 0x9c, 0xbf, 0xca, 0x22, 0xe9, 0x7e, 0xcd, 0xee, 0x3d, 0xfd, 0xd5, 0x66, 0x98, 0x40, 0x34, 0xc0, 0x5c, 0x14, 0xa8, 0xb6, 0x29,
    0xe5, 0xce, 0x0e, 0x44, 0x6b, 0x67, 0xea, 0x3e, 0xec, 0x29, 0x6b, 0xe8, 0x64, 0xb2, 0xa1, 0xb8, 0xdc, 0x83, 0x01, 0xea, 0xa5, 0xfb, 0x12, 0xfc, 0xe1, 0xa5, 0x4c, 0x72, 0x4e, 0x56, 0x6d, 0x02
};

__ALIGN(4) const uint8_t old_pk[64] =
{
    0x84, 0xb7, 0xac, 0x5d, 0xba, 0x00, 0x1c, 0xcd, 0xbe, 0x49, 0x28, 0xf7, 0xcb, 0xd9, 0x74, 0x44, 0x5d, 0xa0, 0x84, 0x94, 0xdb, 0x12, 0xa3, 0x6d, 0xb2, 0x4a, 0x17, 0xa1, 0x3d, 0x05, 0xb9, 0x38, 
    0xdb, 0xa4, 0x21, 0x45, 0x42, 0x10, 0x1b, 0xbf, 0xeb, 0x09, 0xb5, 0x33, 0x67, 0xab, 0x91, 0x14, 0x6d, 0xf5, 0xf1, 0x7d, 0xd6, 0x9d, 0x17, 0x88, 0x20, 0xdf, 0xcf, 0xec, 0x86, 0x64, 0x07, 0xc1
};

#else
#error "Debug public key not valid for production. Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate it"
#endif
