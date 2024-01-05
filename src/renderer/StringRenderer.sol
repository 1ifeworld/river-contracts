// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";

/**
 * @title StringRenderer
 * @author Lifeworld 
 */
contract StringRenderer {
    function decodeUri(address pointer) public view returns (string memory uri) {
        uri = string(SSTORE2.read(pointer));
    }
}