// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"
#include <assert.h>
#include <mutex>
#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 0; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000003f94d1ad391682fe038bf5");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000000000013176bf8d7dfeab4e1db31dc93bc311b436e82ab226b90"); //453354

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1492437608, uint256S("0x0000000000000000000000000000000000000000003f94d1ad391682fe038bf5"), 
            0x207fffff, 1, 50 * COIN);
        genesis.nSolution = ParseHex("00b02acd99b92ef5fa0da67840e7c706bead7b75103fd9eda768b140dd9b8ce44d6f601d56712a7d62660b78445a6816b7f10b7bea02b5e91f92818ddb857554b7f65c015bc19eef7c18b8ccec5f1a360616eac003576f1a03ab08a5ad29a625c0b2b7df69d53d97ff3cbaf297f47102b3f37287cadcdbee9a02e03278b51121946bb09052476276f352db680c48f50bccea9e2610e522789420c0a3c7f4e8e25fc0c979ff0c9aef015b2ad732038681af93a36806435fa61bb8d24a5112f2f43b4907681e58c395dd85be92f706685c6a80165cd98a3c239213f4f4524891a64b3379589e3d7c2da68f5ba361e09dbe61b6c6b1787747158dbbace805240d26409acff3cc16c5965f62d6ca6b291e99853e20827d6759abbb6a4f0b14ddf936f2c5abd9d3a405789d6e48e11ea19690f53fd4b7036ad1c8f94ad910dbbe945486167be9694515e15925d1fa47f9941b01a24b9b27e3a555c04ab244c81806c5c7c4746d8e0b666359754ca5259281c4a487d92159307b1ef8ca1033e965be91984eed4e653c3c5050cde438ba65003cc8c2603350bf22dffb543ef3da4d558c407fb49c0da53db424ea7afdf81c7376806784b904053fab0b13cf2ffe9d8b238bc5dc71d39461b864c362915a490dc4c5b4afd404caa649f59223b888e604c0fd66462a637ade56cbf8e31f61d4845b7bdfdd969e35df5008d916e5b683b9e96884f1c46dbc80b6be05df76f80e5823d7af6974234ff05a33b970dfeadc7e5819be0a4ef27977d785bb5eaab3ba2ef4e4d9c4d8b529351da2a664c8224bd732f319771adece2eb0937bd1100a1bcf5efb85db6cf1d543293da034225c3f5a237a2981d38c1f8e607a9020c93ccbf3412361a2bd17090f7b74a447e6c99bca07811be92533ad812c352fc13ee136887d2824938519d4281e22e336fc0f9ae22c012879483cd7f0eaf15434679a78b45d2a97bf55f90e62c9c9a3058023e5be94eed450e5ae55c394878d2d248430301ca113c023b3d5185fc0b3d52e3f9eb5368bf3493611f125918064d792676b9f83075d2afd06a8c22549cec251cc96a46ed17ffd99c06efbd3825c92acfcb7f4c84df213f6f08aecfd2ac410ba6f1012551a699c0d77debef6a2671ae2bd4cad6d281dae127c5a2679f4ad37acf0d49eb7b24e6e73d5db8f7f04926bc369affa45bd4c34ab812c24fe4214b9ebcb0e53364f10dff373d771825d6ef0485ded5cfc483425307239ba595e7709529264d4ef650d58df7ccbdd63db1b24851ce465ae0786d796c30306309af4e9fb0ab3ae6e472564d741bbf0fde0be8874402a1d07a32b250e8faaa8bb4ff1af7569c6d80e1a3c9074cf5717832dbf56e2744b6e9562dfbba7d3cd2829edc50e3d4cda4d1fef5541d62fd740ced7639dda5e4ffadd0500cf2e1bd56934f1d7b0893313b7aa0b2830618f12b39d596e4bd5357fd2044865b14195e6e8373e8e109fe2de3cd2bce72b3c561f8d6df8a277729682083a170bb06f23d22526dbe5029f7c4c699d7476915a10366dfc7956461dbc0ca2f901afd9a2c5167f54ec2688a1c3c09dfe0b7ff3d60face72aca25b63df26c1cd3e3ec159fe1c7921e488626ddfe8acf07593ff61f844fd27e90c111e49702a4f6c0a9f4e40155bd260c7bc6b12c7a21fdea0cb3d4ffa904fe6ccfb4b55d20b1da3bf08f7210e681a6a00873646ad823ba92171c57747bdbdcea235c1d3890bc51fc96276a5a648b2906a2db3b0d03b4711bb4a97344ea3da22b1736cf15024ebef811980de7acd58a36c5e212440e5fcb9f36f61e20f89a669ce5889478cfec20a14910b768b81cdba2286ee855cbc0bef36f0a765815fd48b4b27a741e13f3fcaa019ffb9c8809e6d3c42a0a5fbef496");

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("68585262d482d83da8d0cbac7191b7e3625db58f81dab413e5a5b0b4493d587b"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
        
        vSeeds.push_back(CDNSSeedData("52.203.150.8", "52.203.150.8"));
        // // Note that of those with the service bits flag, most only support a subset of possible options
        // vSeeds.push_back(CDNSSeedData("bitcoin.sipa.be", "seed.bitcoin.sipa.be", true)); // Pieter Wuille, only supports x1, x5, x9, and xd
        // vSeeds.push_back(CDNSSeedData("bluematt.me", "dnsseed.bluematt.me", true)); // Matt Corallo, only supports x9
        // vSeeds.push_back(CDNSSeedData("dashjr.org", "dnsseed.bitcoin.dashjr.org")); // Luke Dashjr
        // vSeeds.push_back(CDNSSeedData("bitcoinstats.com", "seed.bitcoinstats.com", true)); // Christian Decker, supports x1 - xf
        // vSeeds.push_back(CDNSSeedData("bitcoin.jonasschnelli.ch", "seed.bitcoin.jonasschnelli.ch", true)); // Jonas Schnelli, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"))
            ( 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"))
            ( 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"))
            (105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"))
            (134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"))
            (168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"))
            (193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"))
            (210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"))
            (216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"))
            (225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"))
            (250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"))
            (279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"))
            (295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"))
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000000000000166d612d5595e2b1cd88d71d695fc580af64d8da8658c23 (height 446482).
            1483472411, // * UNIX timestamp of last known number of transactions
            184495391,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            3.2         // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000001f057509eba81aed91");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000128796ee387cf110ccb9d2f36cffaf7f73079c995377c65ac0dcc"); //1079274

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1492437609, uint256S("0x0000000000000000000000000000000000000000003f94d1ad391682fe038bf5"),
            0x207fffff, 1, 50 * COIN);

        genesis.nSolution = ParseHex("002d084a1ef00955876760e6e24ab345785ffc98a218985f61f8d1fbe5ea6b73e6b85041a12e084b46f909feaa54996b46dfd4b333512d370746f2f79d7ef84e67a6248ba125ab841715eb9a6666dea3b1dcf0a60acd967df6577a13c0fe7135ea48092a691fdffd1b27905e24f3a1c509eb379472a83b4676a0af1aea513968325d089719518afe73b16ad7f67df1ed388b473d770e0df0b1b4e1d91da5cde4670f019bf2af3d6e010d4059c9e137a3ac1ea17b06f67e3a4a0cb278c6140df51eec93caadd0ff36333e7db0723ba41447f201da8646563a8499d52aa0494fca34f01556a69baa18a24650859a2f7cdeeb61c0449b999d07351aceb202544b089718356bb205ca0851f374be946f3e7072113c03310947261858d83477e7c7c1fb3f447d7a9920bbf65c179378075f2163144a9f9240f21c4a52124bd2f645511810815d6065a3d8bfb5c67681980dbf03938cbecb5bcd89ef7bc25c68f625127b82df3d3c2c81c246efd01adb08073464ccaa9031531df2d869122e0a708258a2591b3ce58b6dd5860e79d7d9b82b5d0c1fdb3036987fb7cc262bd8c2dd9e90f6179c37056b05c886978946c3f9b118f60b35da1d259a9bbc5b59c330bf1d20b99c3b563d46e5af7ba9e05e901721d5a934321dfd01f524aa088af4426b48171c59c45947533eb2dae081016545b086b047cf959bde782b06a200830cb002e5b16e71eba6442bcd6a619b045d134ad1c850eeafa9f8d57169176f7f436e1b3f75d508380e21ad20769562a7c65b5b51feb33469fcfbc7173539188fa617ed7b1e08da23ea4832dd54b82c2b09bfd32e7767e5cbfc4ba3a6bb367e0148aef35f540c057ed5964d66357435f4cfc3b8b486179b59a6310c72b202b9c3a4dbed75d4f89d5741f94d30b096a413909e8e266c84ebe28ff2142312f9ddc1b4cefdd900399aaffe1195c5dcb6b8abc879686374e6de31091f97e2e896378b87f17b27af30668daf67be1fc2900c942b813a12c7b4e59045cf62cf6c75d30f5757cf2640bd7e0ea14fa99c2083efcb694b4108495e9c1f068cbc678dccffdd44b311dca3f0f5163bbed78a6f0e44839888555f17fd9537547bee5acf55323e4ec81913bdc39d13dd31cbd3a3c874d9de95eb545f2f62272de41b6223ff5f98fd55281750a0754a6d32287a08d30c19df85b9b635cb86348bff9a2dd6775cf4041d70af53af119c93dc89d4d1e7f2086293033e80ff1f763c86aa8ad7086c76f5fc07ce56c5a292946daa28b55ba9e2a53f95671f72ce662b2e4cb3afdf804c08edc2f3bbb551d1b94a9535113e5096a913dde82d3315a2a62bcf3aab921e040b4c507b39c25a3328161ef5ea12602105490de146845547faea6598b422108af07593d0b7b51ff0dec8cec1d53d5acd091f6ea7009c385e6ec5bb204a1c25850eae37a98bc6b5f1fb14dfbe2390d553b4e69d31b9f34813d1e93c9dcd650b1d7fe2a711e60dfb4101ef6850689ec684fad4b2163e8c51cbf7bbcdc34ab615acde98fdfaacbd057316415e5e95eaa043a3f0530bda5cafad3192d614582c60e99609de0ead67c4d74586f11f364f96d2ab8b245b3e90466b3fabe866648d91ebfd12b6073c9f573e953a924261552dbdddd78be9e11dee9913be2c2102e6edb42f62e639302b54f5657f16496b0cef3a5e18fcfda7b7e483afe496f5e8c27a86d2e7c45878a41d594152b2351723fcee943d407036c6b072d902fd2d4df5d07e3a899bed44f7715fecbd59e0aa39f86f054d28c2b92c1aabd3e3f466a6b39dea1eb2db35330a0d123f73a4e96f5ef6746ae1f3bc920d0a1e9e2e0f8a8d1918f1044fa2a748ce5476231ac2f9d76f78191c1b9cc65ad29d6b82c1e1ab426cd0bf32f353b3");
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("522407de829cca09fd146aa623450ed7327da992408fad8fdfa8ffc611a8a3bf"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("testnetbitcoin.jonasschnelli.ch", "testnet-seed.bitcoin.jonasschnelli.ch", true));
        vSeeds.push_back(CDNSSeedData("petertodd.org", "seed.tbtc.petertodd.org", true));
        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));
        vSeeds.push_back(CDNSSeedData("bitcoin.schildbach.de", "testnet-seed.bitcoin.schildbach.de"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")),
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000c2872f8f8a8935c8e3c5862be9038c97d4de2cf37ed496991166928a (height 1063660)
            1483546230,
            12834668,
            0.15
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1492437610, uint256S("0x0000000000000000000000000000000000000000003f94d1ad391682fe038bf5"), 0x207fffff, 1, 50 * COIN);
        genesis.nSolution = ParseHex("021edafc24184f510553e4bebdf7b63971a6b6f323039a718c9bab9ab9a29484239621d2d94557d4f0f010efad151c177f0de0dcd21d01b5e4fb0b4a5d484f1bc401ee5ecc43b75f80c26962695e18b911aaddbf02cd70ed0ca0bbfb5e4ad5c252b81a42f39bd89c2b1a09bafc180b55fe7fcba68b29c3c2631d0c1d9cb70f021e6daa98e7792315a3746e330f52622576d151595d5734dd18a8e6edcc1690d6385b99a7a35e09ac09d5fca76fdb18ddfb6081bc2ca155dfae23be06511ecfa5bf75cc511faec72678e76b1715b9df3d0b261ebf419e2d8d8c596661f797f44c0bcab6315ca10920748be995e2974ba83f635d8037c3d0ef2e78d378156e3c1ccc9fe8a14619f3f06042ba928f1e39586215745612dacb0a40812815a7eadefbb97637389b0225cef1d25b9b1e53fd7952f6455674f8c24ff49810388ff752a0df5c07cce0b3a3a1582b19b26f4e3975070a9ce88695ede4e012fa26bcfacce726749eb75b0f165df64c64aa596417a1913f42f24e6f8ede4e3c0faccde79ba853a3c03613f5802f36dd6d982ef4ca22fa27ec96d0df35c80092b38e2ae4efcb095eb38a09315d173b544ececd6d40c04ac92398cf2b271f8011dd42299f5caf10e68c71c577b8e5235210faf63b0c5686cba0a0026b1df0927b2aa8764b4072df4d61190a3cdf2c0b7fbd8ac1e63f023a1a96709f3ff6c3113376c6cdce928997b5816436e0e634dd405999e6256f49f59de2b99dc34722cba877dc720fad98ea1314c7b4510ef0875bfe487438b33de409e7f35f411116e71c718b5ee27b911772cf61427c6ac7af96a18d15ad935fe457dbad3eac834b8c37e8e17f8cbe11f92dc843228b8f6d48c09c748f5a2cf4dd61590f400d1a8b7ac5c298419affaa34df8552077dbe9cd3ef5e365a6372b82a4329fbb093df01f4745eacf65b10d102cec9f035497f87c83a80688a654c6f3dda9c349e035f4ebf4022b41f90c07382b2ebdb5504b33da1720fa4b1624050377d49625586b73a24e1c10b581ff9428514edd8b3e7f9a88fc64d15c0f1c6d69b5e527608f389701f7813d9cb228385b8a69cf9ba61db335552a7b59a0c1d78acedea55a54874ae8dd5af3a354c152697ecce53bd09ef5041d1d1b4470e7072359d814069634543e5e8af92a504435b2a8b21498559b8b509162e3d601f4e0f5572655752fc67775670bbb16d2434637fe1d08675b04e485c3f539bd6e0f6bf5b2a120fc583a364856f6e326a8d6779f57f8cc47e125c29b71b2395214cf351dcb786ff5f08766cc7db8c770f404f7e0ec79eab58e511fd28b75dbf2d953df75540d5ed5952d076f1da0f369abe66044e5a9d74a5c32452e930a1d1fb097bcd43c62aad01aad3cc1a1e0f29f2a6f809323275ca9e652b59e3f6fe8fa85648c9035a174d92ab5517f1e7f23f4994de691ac66ee18f52a99bc9ce5a985b3df5c5536cdcc5c2a2b33c859f08ca4391ec2c6421b67bd9f0a365e252cf9c9972f7156257cacb96470ab7e286011ddd0aa1c20f502d5b12142b2ed25550e6ddbf23d8d3727d71364194346865b74eb1692eb0018c25ba4a205dc25ec07017223638f673d7b3e7836f45fb83d56021ed4fc1a6bee6e24504aaa476182601ecbb0555933e77aafc7e1f792506fbb62c2963f9575972c3b126725aa3b759ff116a207ce543bdb2bb05da88048bf4e9a166844b3a714d09c255d6c494793db394362ced759e49cbac72b0ca1aed9a2b390aa9130634152523e100cb1023bd2db9104576a527ea4693591605847d5cacb9c6bf704d9a13aa624225ca2ba34439c55f6f61c039c1712f199710c9bd43b2445ca1b71263e7d8b27eb27b7959e58512d431834451c74aaf92a2b1676327119978195743");
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("5f5c29be360df4b011bef110278ce546c00035193670c9ca4d26c8b6098bb627"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 




// printf("Searching for genesis block...\n");
// // This will figure out a valid hash and Nonce if you're
// // creating a different genesis block:
// arith_uint256 hashTarget = hashTarget.SetCompact(genesis.nBits);
// printf("hashTarget = %s\n", hashTarget.ToString().c_str());
// arith_uint256 thash;

// while(true)
// {

//     crypto_generichash_blake2b_state state;
//     std::mutex m_cs;
//     bool cancelSolver = false;
//     std::string solver = GetArg("-equihashsolver", "default");
//     EhInitialiseState(nEquihashN, nEquihashK, state);

//     // I = the block header minus nonce and solution.
//     CEquihashInput I{genesis};
//     CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
//     ss << I;

//     // H(I||...
//     crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

//     // H(I||V||...
//     crypto_generichash_blake2b_state curr_state;
//     curr_state = state;
//     crypto_generichash_blake2b_update(&curr_state,
//                                         genesis.nNonce.begin(),
//                                         genesis.nNonce.size());
//     std::function<bool(std::vector<unsigned char>)> validBlock =
//     [&hashTarget, &m_cs, &cancelSolver, this]
//         (std::vector<unsigned char> soln) {
//         // Write the solution to the hash and compute the result.
//         // printf("- Checking solution against target\n");
//         genesis.nSolution = soln;

//         if (UintToArith256(genesis.GetHash()) > hashTarget) {
//             return false;
//         }

//         if (!CheckEquihashSolution(&genesis, *this)) {
//             return false;
//         }

//         // Found a solution
        
//         // Ignore chain updates caused by us
//         std::lock_guard<std::mutex> lock{m_cs};
//         cancelSolver = false;

//         return true;
//     };
//     std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
//         std::lock_guard<std::mutex> lock{m_cs};
//         return cancelSolver;
//     };
//     if (solver == "tromp") {
//         // Create solver and initialize it.
//         equi eq(1);
//         eq.setstate(&curr_state);

//         // Intialization done, start algo driver.
//         eq.digit0(0);
//         eq.xfull = eq.bfull = eq.hfull = 0;
//         eq.showbsizes(0);
//         for (u32 r = 1; r < WK; r++) {
//             (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
//             eq.xfull = eq.bfull = eq.hfull = 0;
//             eq.showbsizes(r);
//         }
//         eq.digitK(0);

//         // Convert solution indices to byte array (decompress) and pass it to validBlock method.
//         bool ready = false;
//         for (size_t s = 0; s < eq.nsols; s++) {
//             // printf("\rChecking solution %d", int(s+1));
//             std::vector<eh_index> index_vector(PROOFSIZE);
//             for (size_t i = 0; i < PROOFSIZE; i++) {
//                 index_vector[i] = eq.sols[s][i];
//             }
//             std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

//             if (validBlock(sol_char)) {
//                 // If we find a POW solution, do not try other solutions
//                 // because they become invalid as we created a new block in blockchain.
//                 ready = true;
//                 break;
//             }
//         }
//         if (ready) break;
//     } else {
//         try {
//             // If we find a valid block, we rebuild
//             bool found = EhOptimisedSolve(nEquihashN, nEquihashK, curr_state, validBlock, cancelled);
//             if (found) {
//                 break;
//             }
//         } catch (EhSolverCancelledException&) {
//             printf("Equihash solver cancelled\n");
//             std::lock_guard<std::mutex> lock{m_cs};
//             cancelSolver = false;
//         }
//     }

//     genesis.nNonce = ArithToUint256(UintToArith256(genesis.nNonce) + 1);
// }

// printf("block.nTime = %u \n", genesis.nTime);
// printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
// printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
// printf("block.nSolution = %s\n", HexStr(genesis.nSolution.begin(), genesis.nSolution.end()).c_str());
