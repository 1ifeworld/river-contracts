// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";

abstract contract TestSuiteSetup is Test {
    /*//////////////////////////////////////////////////////////////
                                  TYPES
    //////////////////////////////////////////////////////////////*/    

    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `MultiOwnable.ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }    

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant SECP_256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    bytes32 constant ERC6492_DETECTION_SUFFIX = 0x6492649264926492649264926492649264926492649264926492649264926492;
    bytes4 constant ERC1271_SUCCESS = 0x1626ba7e;    

    /*//////////////////////////////////////////////////////////////
                                 GLOBAL EOAs
    //////////////////////////////////////////////////////////////*/    

    Account public trusted = makeAccount("trusted");
    Account public payout = makeAccount("payout");
    Account public recovery = makeAccount("recovery");
    Account public relayer = makeAccount("relayer");
    Account public user = makeAccount("user");
    Account public malicious = makeAccount("malicious");

    /*//////////////////////////////////////////////////////////////
                        SMART ACCOUNT VARIABLES
    //////////////////////////////////////////////////////////////*/ 

    CoinbaseSmartWalletFactory public smartWalletFactory;
    CoinbaseSmartWallet public smartWallet;
    bytes[] owners;
    uint256 nonce;
    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";    
    uint256 passkeyOwnerIndex;     

    function setUp() public virtual {
        // setup fork
        uint256 baseSepoliaFork = vm.createFork('https://sepolia.base.org');
        vm.selectFork(baseSepoliaFork);
        smartWalletFactory = CoinbaseSmartWalletFactory(0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a);       
        // smart wallet variables
        nonce = 0;
        passkeyOwnerIndex = 2;
        owners.push(abi.encode(user.addr));
        owners.push(abi.encode(trusted.addr));
        owners.push(passkeyOwner);
        // NOTE: commented this code out, so in tests you can decide to deploy before/not making any actions/sigs
        // smartWallet = smartWalletFactory.createAccount(owners, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function _deadline() internal view returns (uint256 deadline) {
        deadline = block.timestamp + 1;
    }    

    function _boundPk(uint256 pk) internal pure returns (uint256) {
        return bound(pk, 1, SECP_256K1_ORDER - 1);
    }

    function _boundDeadline(uint40 deadline) internal view returns (uint256) {
        return block.timestamp + uint256(bound(deadline, 1, type(uint40).max));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        sig = abi.encodePacked(r, s, v);
        assertEq(sig.length, 65);
    }       
}