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

#include <stdint.h>
#include <string.h>
#include <numeric>
#include "univalue.h"
#include "amount.h"
#include "rpc/server.h"
#include "rpc/protocol.h"

#include "../wallet/crypter.h"
#include "../wallet/rpcwallet.h"

#include "sync_ext.h"

#include "../cc/CCinclude.h"
#include "../cc/CCtokens.h"
#include "../cc/CCassets.h"

#include "../cc/CCtokens_impl.h"
#include "../cc/CCassetstx_impl.h"

using namespace std;

UniValue assetsaddress(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
	struct CCcontract_info *cp, C; std::vector<unsigned char> pubkey;
	cp = CCinit(&C, EVAL_ASSETS);
	if (fHelp || params.size() > 1)
		throw runtime_error("assetsaddress [pubkey]\n");
	if (ensure_CCrequirements(cp->evalcode) < 0)
		throw runtime_error(CC_REQUIREMENTS_MSG);
	if (params.size() == 1)
		pubkey = ParseHex(params[0].get_str().c_str());
	return CCaddress(cp, (char *)"Assets", pubkey);
}

UniValue tokenaddress(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C, EVAL_TOKENS);
    if ( fHelp || params.size() > 1 )
        throw runtime_error("tokenaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    if ( params.size() == 1 )
        pubkey = ParseHex(params[0].get_str().c_str());
    return CCaddress(cp, "Tokens", pubkey, false);
}

UniValue tokenv2address(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    struct CCcontract_info *cp,C; 
    vuint8_t pubkey;

    cp = CCinit(&C, EVAL_TOKENSV2);
    if (fHelp || params.size() > 1)
        throw runtime_error("tokenv2address [pubkey]\n");
    if (ensure_CCrequirements(cp->evalcode) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
    if (params.size() == 1)
        pubkey = ParseHex(params[0].get_str().c_str());
    return CCaddress(cp, "Tokensv2", pubkey, true);  
}

UniValue assetsv2address(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    struct CCcontract_info *cp,C; 
    vuint8_t pubkey;

    cp = CCinit(&C, EVAL_ASSETSV2);
    if (fHelp || params.size() > 1)
        throw runtime_error("assetsv2address [pubkey]\n");
    if (ensure_CCrequirements(cp->evalcode) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
    if (params.size() == 1)
        pubkey = ParseHex(params[0].get_str().c_str());
    return CCaddress(cp, "Assetsv2", pubkey, true);  
}

UniValue tokenlist(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    uint256 tokenid;
    if (fHelp || params.size() > 0)
        throw runtime_error("tokenlist\n");
        
    if (ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    return TokenList();
}
UniValue tokenv2list(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    uint256 tokenid;
    if (fHelp || params.size() > 0)
        throw runtime_error("tokenv2list\n");

    if (ensure_CCrequirements(EVAL_TOKENSV2) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    return TokenV2List();}

template <class V>
static UniValue tokeninfo(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    uint256 tokenid;
    if ( fHelp || params.size() != 1 )
        throw runtime_error(name + " tokenid\n");
    if ( ensure_CCrequirements(V::EvalCode()) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    return TokenInfo<V>(tokenid);
}

UniValue tokeninfo(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokeninfo<TokensV1>("tokeninfo", params, fHelp, remotepk);
}
UniValue tokenv2info(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokeninfo<TokensV2>("tokenv2info", params, fHelp, remotepk);
}

template <class T, class A>
UniValue tokenorders(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    uint256 tokenid;
    uint8_t evalcodeNFT = 0;
    const CPubKey emptypk;

    if ( fHelp || params.size() > 2 )
        throw runtime_error(name + " [tokenid|'*'] [evalcode]\n"
                            "returns token orders for the tokenid or all available token orders if tokenid is not set\n"
                            "returns also NFT ask orders if NFT evalcode is set\n" "\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
	if (params.size() >= 1) 
    {
        if (params[0].get_str() != "*")
        {
		    tokenid = Parseuint256((char *)params[0].get_str().c_str());
		    if (tokenid == zeroid) 
			    throw runtime_error("incorrect tokenid\n");
        }
    }
    if (params.size() == 2)
        evalcodeNFT = strtol(params[1].get_str().c_str(), NULL, 0);  // supports also 0xEE-like values

    if (TokensIsVer1Active(NULL))
        return AssetOrders<T, A>(tokenid, emptypk, evalcodeNFT);
    else
        return tokensv0::AssetOrders(tokenid, emptypk, evalcodeNFT);
}

UniValue tokenorders(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenorders<TokensV1, AssetsV1>("tokenorders", params, fHelp, remotepk);
}
UniValue tokenv2orders(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenorders<TokensV2, AssetsV2>("tokenv2orders", params, fHelp, remotepk);
}

template <class T, class A>
UniValue mytokenorders(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    uint256 tokenid;
    if (fHelp || params.size() > 1)
        throw runtime_error(name + " [evalcode]\n"
                            "returns all the token orders for mypubkey\n"
                            "if evalcode is set then returns mypubkey's token orders for non-fungible tokens with this evalcode\n" "\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
    uint8_t evalcodeNFT = 0;
    if (params.size() == 1)
        evalcodeNFT = strtol(params[0].get_str().c_str(), NULL, 0);  // supports also 0xEE-like values
    
    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);

    if (TokensIsVer1Active(NULL))
        return AssetOrders<T, A>(zeroid, mypk, evalcodeNFT);
    else
        return tokensv0::AssetOrders(zeroid, Mypubkey(), evalcodeNFT);

}

UniValue mytokenorders(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return mytokenorders<TokensV1, AssetsV1>("mytokenorders", params, fHelp, remotepk);
}
UniValue mytokenv2orders(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return mytokenorders<TokensV2, AssetsV2>("mytokenv2orders", params, fHelp, remotepk);
}

template <class V>
static UniValue tokenbalance(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); uint256 tokenid; uint64_t balance; std::vector<unsigned char> vpubkey; struct CCcontract_info *cp,C;
	CCerror.clear();

    if ( fHelp || params.size() < 1 || params.size() > 2 )
        throw runtime_error(name + " tokenid [pubkey]\n");
    if ( ensure_CCrequirements(V::EvalCode()) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    
	//LOCK(cs_main);

    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    if ( params.size() == 2 )
        vpubkey = ParseHex(params[1].get_str().c_str());
    else 
		vpubkey = Mypubkey();

    balance = GetTokenBalance<V>(pubkey2pk(vpubkey), tokenid, false);

	if (CCerror.empty()) {
		char destaddr[KOMODO_ADDRESS_BUFSIZE];

		result.push_back(Pair("result", "success"));
        cp = CCinit(&C, V::EvalCode());
		if (GetCCaddress(cp, destaddr, pubkey2pk(vpubkey), V::IsMixed()) != 0)
			result.push_back(Pair("CCaddress", destaddr));

		result.push_back(Pair("tokenid", params[0].get_str()));
		result.push_back(Pair("balance", (int64_t)balance));
	}
	else {
		result = MakeResultError(CCerror);
	}

    return result;
}

UniValue tokenbalance(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenbalance<TokensV1>("tokenbalance", params, fHelp, remotepk);
}
UniValue tokenv2balance(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenbalance<TokensV2>("tokenv2balance", params, fHelp, remotepk);
}

uint256 fvintxid;
int32_t fvinn;

template <class V>
static UniValue tokencreate(const std::string& fname, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ);
    std::string name, description, hextx; 
    std::vector<uint8_t> nonfungibleData;
    int64_t supply; // changed from uin64_t to int64_t for this 'if ( supply <= 0 )' to work as expected

    CCerror.clear();

    if ( fHelp || params.size() > 4 || params.size() < 2 )
        throw runtime_error(fname + " name supply [description][nft data]\n");
    if ( ensure_CCrequirements(V::EvalCode()) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    LOCK2(cs_main, pwalletMain->cs_wallet);  // remote call not supported yet

    name = params[0].get_str();
    if (name.size() == 0 || name.size() > 32)   
        return MakeResultError("Token name must not be empty and up to 32 characters");

    supply = AmountFromValue(params[1]);   
    if (supply <= 0)    
        return MakeResultError("Token supply must be positive");
    
    
    if (params.size() >= 3)     {
        description = params[2].get_str();
        if (description.size() > 4096)   
            return MakeResultError("Token description must be <= " + std::to_string(4096));  // allowed > MAX_SCRIPT_ELEMENT_SIZE
    }
    
    if (params.size() >= 4)    {
        nonfungibleData = ParseHex(params[3].get_str());
        // looks like bigger than 520 data is available in opreturn 
        // if (nonfungibleData.size() > MAX_SCRIPT_ELEMENT_SIZE) // script element limit
        //    return MakeResultError("Non-fungible data size must be <= " + std::to_string(MAX_SCRIPT_ELEMENT_SIZE));
        
        if( nonfungibleData.empty() ) 
            return MakeResultError("Non-fungible data incorrect");
    }

    hextx = CreateTokenLocal<V>(0, supply, name, description, nonfungibleData);
    RETURN_IF_ERROR(CCerror);

    if( hextx.size() > 0 )     
        return MakeResultSuccess(hextx);
    else
        return MakeResultError("could not create token");
}

UniValue tokencreate(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencreate<TokensV1>("tokencreate", params, fHelp, remotepk);
}
UniValue tokenv2create(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencreate<TokensV2>("tokenv2create", params, fHelp, remotepk);
}

template <class V>
static UniValue tokentransfer(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    std::string hex; 
    CAmount amount; 
    uint256 tokenid;
    
    CCerror.clear();

    if ( fHelp /*|| params.size() != 3*/)
        throw runtime_error(name + " tokenid destpubkey amount \n");
    if ( ensure_CCrequirements(V::EvalCode()) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");    
    LOCK2(cs_main, pwalletMain->cs_wallet);   // remote call not supported yet
    
    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    vuint8_t vpubkey(ParseHex(params[1].get_str().c_str()));
	amount = atoll(params[2].get_str().c_str()); 
    if( tokenid == zeroid )    
        return MakeResultError("invalid tokenid");
    if (vpubkey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) 
        return MakeResultError("invalid destpubkey");    
    if( amount <= 0 )    
        return MakeResultError("amount must be positive");

fvintxid = zeroid;
fvinn = -1;
if (params.size() == 5) {
    fvintxid = Parseuint256((char *)params[3].get_str().c_str());
    fvinn = atoll(params[4].get_str().c_str()); 
}
    
    hex = TokenTransfer<V>(0, tokenid, pubkey2pk(vpubkey), amount);
    RETURN_IF_ERROR(CCerror);
    if (hex.size() > 0)
        return MakeResultSuccess(hex);
    else
        return MakeResultError("could not transfer token");
}

UniValue tokentransfer(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokentransfer<TokensV1>("tokentransfer", params, fHelp, remotepk);
}
UniValue tokenv2transfer(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokentransfer<TokensV2>("tokenv2transfer", params, fHelp, remotepk);
}

template <class V>
UniValue tokentransfermany(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    std::string hex; 
    CAmount amount; 
    uint256 tokenid;
    const CAmount txfee = 10000;
    
    CCerror.clear();

    if ( fHelp || params.size() < 3)
        throw runtime_error(name + " tokenid1 tokenid2 ... destpubkey amount \n");
    if ( ensure_CCrequirements(V::EvalCode()) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);

    std::vector<uint256> tokenids;
    int i = 0;
    for (; i < params.size() - 2; i ++)
    {
        uint256 tokenid = Parseuint256((char *)params[i].get_str().c_str());
        if( tokenid == zeroid )    
            return MakeResultError("invalid tokenid");
        tokenids.push_back(tokenid);
    }
    CPubKey destpk = pubkey2pk(ParseHex(params[i++].get_str().c_str()));
	if (destpk.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) 
        return MakeResultError("invalid destpubkey");
    
    amount = atoll(params[i].get_str().c_str()); 
    if( amount <= 0 )    
        return MakeResultError("amount must be positive");
    
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    LOCK2(cs_main, pwalletMain->cs_wallet);  // remote call not supported yet

    CPubKey mypk = remotepk.IsValid() ? remotepk : pubkey2pk(Mypubkey());

    CMutableTransaction mtx;
    struct CCcontract_info *cpTokens, CTokens;
    cpTokens = CCinit(&CTokens, V::EvalCode());

    UniValue beginResult = TokenBeginTransferTx<V>(mtx, cpTokens, remotepk, txfee);
    if (ResultIsError(beginResult)) 
        return beginResult;
    
    for (const auto &tokenid : tokenids)
    {
        TokenDataTuple tokenData;
        vuint8_t vnftData;
        GetTokenData<V>(tokenid, tokenData, vnftData);
        CCwrapper probeCond;
        if (vnftData.size() > 0)
            probeCond.reset( V::MakeTokensCCcond1(vnftData[0], mypk) );
        else
            probeCond.reset( MakeCCcond1(V::EvalCode(), mypk) );

        uint8_t mypriv[32];
        Myprivkey(mypriv);
        
        char tokenaddr[KOMODO_ADDRESS_BUFSIZE];
        cpTokens->evalcodeNFT = vnftData.size() > 0 ? vnftData[0] : 0;
        GetTokensCCaddress(cpTokens, tokenaddr, mypk, V::IsMixed());

        UniValue addtxResult = TokenAddTransferVout<V>(mtx, cpTokens, remotepk, tokenid, tokenaddr, { destpk }, {probeCond, mypriv}, amount, false);
        memset(mypriv, '\0', sizeof(mypriv));
        if (ResultIsError(addtxResult)) 
            return MakeResultError( ResultGetError(addtxResult) + " " + tokenid.GetHex() );
    }
    UniValue sigData = TokenFinalizeTransferTx<V>(mtx, cpTokens, remotepk, txfee, CScript());
    RETURN_IF_ERROR(CCerror);
    if (ResultHasTx(sigData) > 0)
        result = sigData;
    else
        result = MakeResultError("could not transfer token: " + ResultGetError(sigData));
    return result;
}

UniValue tokentransfermany(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokentransfermany<TokensV1>("tokentransfermany", params, fHelp, remotepk);
}
UniValue tokenv2transfermany(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokentransfermany<TokensV2>("tokenv2transfermany", params, fHelp, remotepk);
}

UniValue tokenconvert(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t evalcode; int64_t amount; uint256 tokenid;
    CCerror.clear();
    if ( fHelp || params.size() != 4 )
        throw runtime_error("tokenconvert evalcode tokenid pubkey amount\n");
    if ( ensure_CCrequirements(EVAL_ASSETS) < 0 )
        throw runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    LOCK2(cs_main, pwalletMain->cs_wallet);
    evalcode = atoi(params[0].get_str().c_str());
    tokenid = Parseuint256((char *)params[1].get_str().c_str());
    std::vector<unsigned char> pubkey(ParseHex(params[2].get_str().c_str()));
    //amount = atol(params[3].get_str().c_str());
	amount = atoll(params[3].get_str().c_str()); // dimxy changed to prevent loss of significance
    if( tokenid == zeroid )
        return MakeResultError("invalid tokenid");

    if( amount <= 0 )
        return MakeResultError("amount must be positive");

	return MakeResultError("deprecated");

/*    hex = AssetConvert(0,tokenid,pubkey,amount,evalcode);
    if (amount > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt convert tokens");
    } else {
        ERR_RESULT("amount must be positive");
    }
    return(result); */
}

template <class T, class A>
UniValue tokenbid(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    int64_t bidamount,numtokens; 
    std::string hex; 
    uint256 tokenid;

    CCerror.clear();
    if ( fHelp || params.size() != 3 )
        throw runtime_error(name + " numtokens tokenid price\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

	numtokens = atoll(params[0].get_str().c_str());  
    tokenid = Parseuint256((char *)params[1].get_str().c_str());
    CAmount price = AmountFromValue(params[2]);
    bidamount = (price * numtokens);
    if (price <= 0)
        return MakeResultError("price must be positive");
      
    if (tokenid == zeroid)
        return MakeResultError("invalid tokenid");
        
    if (bidamount <= 0)
        return MakeResultError("bid amount must be positive");

    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    
    if (TokensIsVer1Active(NULL))
        result = CreateBuyOffer<T, A>(mypk, 0, bidamount, tokenid, numtokens);
    else  {
        hex = tokensv0::CreateBuyOffer(0, bidamount, tokenid, numtokens);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not create bid");
    }
    RETURN_IF_ERROR(CCerror);
    return result;
}

UniValue tokenbid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenbid<TokensV1, AssetsV1>("tokenbid", params, fHelp, remotepk);
}
UniValue tokenv2bid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenbid<TokensV2, AssetsV2>("tokenv2bid", params, fHelp, remotepk);
}

template <class T, class A>
UniValue tokencancelbid(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t i; uint256 tokenid,bidtxid;
    CCerror.clear();
    if (fHelp || params.size() != 2)
        throw runtime_error(name + " tokenid bidtxid\n");

    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    bidtxid = Parseuint256((char *)params[1].get_str().c_str());
    if ( tokenid == zeroid || bidtxid == zeroid )
        return MakeResultError("invalid parameter");

    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    if (TokensIsVer1Active(NULL))
        result = CancelBuyOffer<T, A>(mypk, 0,tokenid,bidtxid);
    else  {
        hex = tokensv0::CancelBuyOffer(0,tokenid,bidtxid);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not cancel bid");
    }
    RETURN_IF_ERROR(CCerror);
    return result;
}

UniValue tokencancelbid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencancelbid<TokensV1, AssetsV1>("tokencancelbid", params, fHelp, remotepk);
}
UniValue tokenv2cancelbid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencancelbid<TokensV2, AssetsV2>("tokenv2cancelbid", params, fHelp, remotepk);
}

template <class T, class A>
UniValue tokenfillbid(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    int64_t fillamount; 
    std::string hex; 
    uint256 tokenid,bidtxid;

    CCerror.clear();

    if (fHelp || params.size() != 3 && params.size() != 4)
        throw runtime_error(name + " tokenid bidtxid fillamount [unit_price]\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());
    
    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    bidtxid = Parseuint256((char *)params[1].get_str().c_str());
    fillamount = atoll(params[2].get_str().c_str());		
    if (fillamount <= 0)
        return MakeResultError("fillamount must be positive");
          
    if (tokenid == zeroid || bidtxid == zeroid)
        return MakeResultError("must provide tokenid and bidtxid");
    
    CAmount unit_price = 0LL;
    if (params.size() == 4)
	    unit_price = AmountFromValue(params[3].get_str().c_str());
    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    if (TokensIsVer1Active(NULL))	 
        result = FillBuyOffer<T, A>(mypk, 0, tokenid, bidtxid, fillamount, unit_price);
    else      {
        hex = tokensv0::FillBuyOffer(0, tokenid, bidtxid, fillamount);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not fill bid");
    }
    RETURN_IF_ERROR(CCerror);
    return result;
}

UniValue tokenfillbid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenfillbid<TokensV1, AssetsV1>("tokenfillbid", params, fHelp, remotepk);
}
UniValue tokenv2fillbid(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenfillbid<TokensV2, AssetsV2>("tokenv2fillbid", params, fHelp, remotepk);
}

template <class T, class A>
UniValue tokenask(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    int64_t askamount, numtokens; 
    std::string hex; 
    uint256 tokenid;

    CCerror.clear();
    if (fHelp || params.size() != 3)
        throw runtime_error(name + " numtokens tokenid price\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
    
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

	numtokens = atoll(params[0].get_str().c_str());			
    tokenid = Parseuint256((char *)params[1].get_str().c_str());
    CAmount price = AmountFromValue(params[2]);
    askamount = (price * numtokens);
    if (tokenid == zeroid || numtokens <= 0 || price <= 0 || askamount <= 0)
        return MakeResultError("invalid parameter");

    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    if (TokensIsVer1Active(NULL))	 
        result = CreateSell<T, A>(mypk, 0, numtokens, tokenid, askamount);
    else      {
        hex = tokensv0::CreateSell(0, numtokens, tokenid, askamount);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not create ask");
    }
    RETURN_IF_ERROR(CCerror);    
    return result;
}

UniValue tokenask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenask<TokensV1, AssetsV1>("tokenask", params, fHelp, remotepk);
}
UniValue tokenv2ask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenask<TokensV2, AssetsV2>("tokenv2ask", params, fHelp, remotepk);
}

// not implemented
UniValue tokenswapask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    static uint256 zeroid;
    UniValue result(UniValue::VOBJ); int64_t askamount,numtokens; std::string hex; double price; uint256 tokenid,otherid;

    CCerror.clear();
    if (fHelp || params.size() != 4)
        throw runtime_error("tokenswapask numtokens tokenid otherid price\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

    throw runtime_error("tokenswapask not supported\n");

	numtokens = atoll(params[0].get_str().c_str());			
    tokenid = Parseuint256((char *)params[1].get_str().c_str());
    otherid = Parseuint256((char *)params[2].get_str().c_str());
    price = atof(params[3].get_str().c_str());
    askamount = (price * numtokens);
    hex = CreateSwap<TokensV2, AssetsV2>(0,numtokens,tokenid,otherid,askamount);
    RETURN_IF_ERROR(CCerror);
    if (price > 0 && numtokens > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create swap");
    } else {
        ERR_RESULT("price and numtokens must be positive");
    }
    return result;
}

template <class T, class A>
UniValue tokencancelask(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t i; uint256 tokenid,asktxid;

    CCerror.clear();
    if (fHelp || params.size() != 2)
        throw runtime_error(name + " tokenid asktxid\n");

    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    asktxid = Parseuint256((char *)params[1].get_str().c_str());
    if (tokenid == zeroid || asktxid == zeroid)
        return MakeResultError("invalid parameter");

    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    if (TokensIsVer1Active(NULL))	 
        result = CancelSell<T, A>(mypk, 0, tokenid, asktxid);
    else    {
        hex = tokensv0::CancelSell(0, tokenid, asktxid);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not cancel ask");
    }
    RETURN_IF_ERROR(CCerror);
    return(result);
}

UniValue tokencancelask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencancelask<TokensV1, AssetsV1>("tokencancelask", params, fHelp, remotepk);
}
UniValue tokenv2cancelask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokencancelask<TokensV2, AssetsV2>("tokenv2cancelask", params, fHelp, remotepk);
}

template <class T, class A>
UniValue tokenfillask(const std::string& name, const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    UniValue result(UniValue::VOBJ); 
    int64_t fillunits; 
    std::string hex; 
    uint256 tokenid,asktxid;

    if (fHelp || params.size() != 3 && params.size() != 4)
        throw runtime_error(name + " tokenid asktxid fillunits [unitprice]\n");
    if (ensure_CCrequirements(A::EvalCode()) < 0 || ensure_CCrequirements(T::EvalCode()) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);

    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    asktxid = Parseuint256((char *)params[1].get_str().c_str());
	fillunits = atoll(params[2].get_str().c_str());	 
    if (fillunits <= 0)
        return MakeResultError("fillunits must be positive");
    if (tokenid == zeroid || asktxid == zeroid)
        return MakeResultError("invalid parameter");
    CAmount unit_price = 0LL;
    if (params.size() == 4)
	    unit_price = AmountFromValue(params[3].get_str().c_str());	 

    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    if (TokensIsVer1Active(NULL))	 
        result = FillSell<T, A>(mypk, 0, tokenid, zeroid, asktxid, fillunits, unit_price);
    else    {
        hex = tokensv0::FillSell(0, tokenid, zeroid, asktxid, fillunits);
        if (!hex.empty())
            result = MakeResultSuccess(hex);
        else
            result = MakeResultError("could not fill ask");
    }
    RETURN_IF_ERROR(CCerror);
    return result;
}

UniValue tokenfillask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenfillask<TokensV1, AssetsV1>("tokenfillask", params, fHelp, remotepk);
}
UniValue tokenv2fillask(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    return tokenfillask<TokensV2, AssetsV2>("tokenv2fillask", params, fHelp, remotepk);
}

// not used yet
UniValue tokenfillswap(const UniValue& params, bool fHelp, const CPubKey& remotepk)
{
    static uint256 zeroid;
    UniValue result(UniValue::VOBJ); 
    int64_t fillunits; std::string hex; uint256 tokenid,otherid,asktxid;

    CCerror.clear();
    if (fHelp || params.size() != 4 && params.size() != 5)
        throw runtime_error("tokenfillswap tokenid otherid asktxid fillunits [unitprice]\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0)
        throw runtime_error(CC_REQUIREMENTS_MSG);
        
    if (!EnsureWalletIsAvailable(false))
        throw runtime_error("wallet is required");
    CONDITIONAL_LOCK2(cs_main, pwalletMain->cs_wallet, !remotepk.IsValid());

    throw runtime_error("tokenfillswap not supported\n");

    tokenid = Parseuint256((char *)params[0].get_str().c_str());
    otherid = Parseuint256((char *)params[1].get_str().c_str());
    asktxid = Parseuint256((char *)params[2].get_str().c_str());
    //fillunits = atol(params[3].get_str().c_str());
	fillunits = atoll(params[3].get_str().c_str());  // dimxy changed to prevent loss of significance
    CAmount unit_price = 0LL;
    if (params.size() == 5)
	    unit_price = AmountFromValue(params[4].get_str().c_str());
    CPubKey mypk;
    SET_MYPK_OR_REMOTE(mypk, remotepk);
    result = FillSell<TokensV1, AssetsV1>(mypk,0,tokenid,otherid,asktxid,fillunits, unit_price);
    RETURN_IF_ERROR(CCerror);
    if (fillunits > 0) {
        if ( hex.size() > 0 ) {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt fill bid");
    } else {
        ERR_RESULT("fillunits must be positive");
    }
    return result;
}


static const CRPCCommand commands[] =
{ //  category              name                actor (function)        okSafeMode
  //  -------------- ------------------------  -----------------------  ----------
     // tokens & assets
	{ "tokens",       "assetsaddress",    &assetsaddress,      true },
	{ "tokens v2",       "assetsv2address",    &assetsv2address,      true },

    { "tokens",       "tokeninfo",        &tokeninfo,         true },
    { "tokens v2",       "tokenv2info",      &tokenv2info,         true },
    { "tokens",       "tokenlist",        &tokenlist,         true },
    { "tokens v2",       "tokenv2list",      &tokenv2list,         true },
    { "tokens",       "tokenorders",      &tokenorders,       true },
    { "tokens v2",       "tokenv2orders",      &tokenv2orders,       true },
    { "tokens",       "mytokenorders",    &mytokenorders,     true },
    { "tokens v2",       "mytokenv2orders",    &mytokenv2orders,     true },
    { "tokens",       "tokenaddress",     &tokenaddress,      true },
    { "tokens v2",       "tokenv2address",   &tokenv2address,      true },
    { "tokens",       "tokenbalance",     &tokenbalance,      true },
    { "tokens v2",       "tokenv2balance",   &tokenv2balance,      true },
    { "tokens",       "tokencreate",      &tokencreate,       true },
    { "tokens v2",       "tokenv2create",    &tokenv2create,       true },
    { "tokens",       "tokentransfer",    &tokentransfer,     true },
    { "tokens v2",       "tokenv2transfer",     &tokenv2transfer,     true },
    { "tokens",       "tokentransfermany",   &tokentransfermany,     true },
    { "tokens v2",       "tokenv2transfermany", &tokenv2transfermany,     true },
    { "tokens",       "tokenbid",         &tokenbid,          true },
    { "tokens",       "tokencancelbid",   &tokencancelbid,    true },
    { "tokens",       "tokenfillbid",     &tokenfillbid,      true },
    { "tokens",       "tokenask",         &tokenask,          true },
    //{ "tokens",       "tokenswapask",     &tokenswapask,      true },
    { "tokens",       "tokencancelask",   &tokencancelask,    true },
    { "tokens",       "tokenfillask",     &tokenfillask,      true },
    { "tokens v2",       "tokenv2bid",         &tokenv2bid,          true },
    { "tokens v2",       "tokenv2cancelbid",   &tokenv2cancelbid,    true },
    { "tokens v2",       "tokenv2fillbid",     &tokenv2fillbid,      true },
    { "tokens v2",       "tokenv2ask",         &tokenv2ask,          true },
    //{ "tokens",       "tokenswapask",     &tokenswapask,      true },
    { "tokens v2",       "tokenv2cancelask",   &tokenv2cancelask,    true },
    { "tokens v2",       "tokenv2fillask",     &tokenv2fillask,      true },
    //{ "tokens",       "tokenfillswap",    &tokenfillswap,     true },
    { "tokens",       "tokenconvert", &tokenconvert, true },
};

void RegisterTokensRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
