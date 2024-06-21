// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";

abstract contract TestSuiteSetup is Test {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant SECP_256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    Account public trusted = makeAccount("trusted");
    Account public relayer = makeAccount("relayer");
    Account public user = makeAccount("user");
    Account public malicious = makeAccount("malicious");
    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    // bytes passkeyOwner =
    //     hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    
    bytes passkeyOwner = 
        hex"93a1c75589426929fa3b4bb2d6208d147feb4b82fba06ffb66d8f8c609ab121a091d01faef625faf12e4f656ec9ef7c6a1976064b366ab5ebdb6c6b15f116820";

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {}

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

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
