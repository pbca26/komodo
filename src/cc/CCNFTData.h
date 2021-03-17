#ifndef CC_NFTDATA_H
#define CC_NFTDATA_H

#include "CCinclude.h"

bool NFTDataValidate(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);

#endif
