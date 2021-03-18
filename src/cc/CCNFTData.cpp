/******************************************************************************
* Copyright  2014-2019 The SuperNET Developers.                             *
*                                                                            *
* See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
* the top-level directory of this distribution for the individual copyright  *
* holder information and the developer policies on copyright and licensing.  *
*                                                                            *
* Unless otherwise agreed in a custom licensing agreement, no part of the    *
* SuperNET software, including this file may be copied, modified, propagated *
* or distributed except according to the terms contained in the LICENSE file *
*                                                                            *
* Removal or modification of this copyright notice is prohibited.            *
*                                                                            *
******************************************************************************/

#include "CCtokens.h"
#include "CCNFTData.h"

// nft field id:
enum nftFieldId : uint8_t {
    NFTFLD_NONE = 0x0, 
    NFTFLD_ID = 0x1, 
    NFTFLD_URL = 0x2 
};

enum nftFieldType : uint8_t {
    NFTTYP_INVALID = 0x0, 
    NFTTYP_COMPACTSIZE = 0x1, 
    NFTTYP_VARBUFFER = 0x2 
};

static const std::map<nftFieldId, nftFieldType> nftFieldDesc = {
    { NFTFLD_ID, NFTTYP_COMPACTSIZE },
    { NFTFLD_URL, NFTTYP_VARBUFFER },
};


static bool ValidateNftData(const vuint8_t &vdata)
{
    std::set<nftFieldId> fieldIds;
    if (vdata.size() > 0 && vdata[0] == EVAL_NFTDATA) {
        uint8_t evalCode;
        uint8_t id;
        uint64_t uint64Value;
        vuint8_t vuint8Value;

        bool invalidFieldType = false;
        bool hasDuplicates = false;

        if(E_UNMARSHAL(vdata, ss >> evalCode; // evalcode in the first byte
            while(!ss.eof()) {
                ss >> id; 
                auto itDesc = nftFieldDesc.find((nftFieldId)id);
                switch(itDesc != nftFieldDesc.end() ? itDesc->second : NFTTYP_INVALID) {
                    case NFTTYP_COMPACTSIZE:
                        std::cerr << "parsing compactsize" << std::endl;
                        ss >> COMPACTSIZE(uint64Value);
                        LOGSTREAMFN(cctokens_log, CCLOG_DEBUG1, stream << "compactsize=" << uint64Value << std::endl); 
                        break;
                    case NFTTYP_VARBUFFER:
                        std::cerr << "parsing varbuffer" << std::endl;
                        ss >> vuint8Value;
                        LOGSTREAMFN(cctokens_log, CCLOG_DEBUG1, stream << "varbuffer=" << HexStr(vuint8Value) << std::endl); 
                        break;
                    default:
                        LOGSTREAMFN(cctokens_log, CCLOG_DEBUG1, stream << "id not allowed (" << (int)id << ")" << std::endl);
                        invalidFieldType = true;
                        break;
                }
                if (invalidFieldType)
                    break;
                if (fieldIds.count((nftFieldId)id) > 0)
                    hasDuplicates = true;
                else
                    fieldIds.insert((nftFieldId)id);
            }
        )) 
        {
            if (invalidFieldType)
                return false;
            if (!hasDuplicates)  {
                if (fieldIds.size() > 0)  
                    return true;
                else 
                    LOGSTREAM(cctokens_log, CCLOG_DEBUG1, stream << __func__ << " no nft properties" << std::endl);
            }
            else 
                LOGSTREAM(cctokens_log, CCLOG_DEBUG1, stream << __func__ << " duplicates in nft data " << std::endl);            
        }
        else 
           LOGSTREAM(cctokens_log, CCLOG_DEBUG1, stream << __func__ << " could not unmarshal nft data" << std::endl);
    }
    return false;
}

bool ValidateNFTOpretV1(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, const CScript &opret)
{
    uint256 tokenid;
    std::vector<CPubKey> vpks;
    std::vector<vuint8_t> voprets;
    if (DecodeTokenOpRetV1(opret, tokenid, vpks, voprets) == 0)
        return eval->Error("could not decode opdrop token data");
    
    for(auto const &vin : tx.vin)
    {
        if (vin.prevout.hash == tokenid)    // for token v1 check directly spent token create tx
        {
            CTransaction vintx;
            uint256 hashBlock;
            vuint8_t vorigpk;
            std::string name, desc;
            std::vector<vuint8_t> vcroprets;

            if (!myGetTransaction(vin.prevout.hash, vintx, hashBlock))
                return eval->Error("could load vintx");
            if (DecodeTokenCreateOpRetV1(vintx.vout.back().scriptPubKey, vorigpk, name, desc, vcroprets) == 0)
                return eval->Error("could not decode token create tx opreturn");
            if (vcroprets.size() == 0)
                return eval->Error("no nft data in opreturn");
            if (!ValidateNftData(vcroprets[0]))
                return eval->Error("nft data invalid");
        }
    }
    return true;
}

bool ValidateNFTOpretV2(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, const CScript &opret)
{
    vuint8_t vorigpk;
    std::string name, desc;
    std::vector<vuint8_t> vcroprets;

    if (DecodeTokenCreateOpRetV2(opret, vorigpk, name, desc, vcroprets) == 0)
        return eval->Error("could not decode opdrop token data");
    if (vcroprets.size() == 0)
        return eval->Error("no nft data in opreturn");
    if (!ValidateNftData(vcroprets[0]))
        return eval->Error("nft data invalid");
    return true;
}

bool NFTDataValidate(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    if (tx.vout.size() < 1)
        return eval->Error("no vouts");

    vuint8_t vopret;
    uint8_t evalTokens;
    int nNoTokenOpdrops = 0;

    // find NFT vout:
    for (int i = 0; i < tx.vout.size(); i ++)   {
        //uint256 tokenid;
        //std::string errstr;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition()) 
        {
            CScript ccdata;
            if (GetCCDropAsOpret(tx.vout[i].scriptPubKey, ccdata) &&
                GetOpReturnData(ccdata, vopret) &&
                vopret.size() > 2 &&
                (vopret[0] == EVAL_TOKENS || vopret[0] == EVAL_TOKENSV2))
            {
                if (vopret[0] == EVAL_TOKENS)   
                    return ValidateNFTOpretV1(cp, eval, tx, ccdata);
                else 
                    return ValidateNFTOpretV2(cp, eval, tx, ccdata);
            }
            else
            {
                nNoTokenOpdrops ++;
            }
        }
    }

    if (nNoTokenOpdrops > 0)
    {
        // if there are cc vouts with no token data
        // should be last vout opreturn for them
        if (GetOpReturnData(tx.vout.back().scriptPubKey, vopret) &&
            vopret.size() > 2 &&
            (vopret[0] == EVAL_TOKENS || vopret[0] == EVAL_TOKENSV2))
        {
            if (vopret[0] == EVAL_TOKENS)   
                return ValidateNFTOpretV1(cp, eval, tx, tx.vout.back().scriptPubKey);
            else 
                return ValidateNFTOpretV2(cp, eval, tx, tx.vout.back().scriptPubKey);
        }
    }

    return eval->Error("no nft data found");
}

