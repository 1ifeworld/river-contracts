// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Pausable} from "openzeppelin-contracts/utils/Pausable.sol";
import {IIdRegistry} from "./interfaces/IIdRegistry.sol";
import {Auth} from "./abstract/Auth.sol";
import {Hash} from "./abstract/Hash.sol";
import {Salt} from "./abstract/Salt.sol";
import {Signatures} from "./abstract/signatures/Signatures.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {Trust} from "./abstract/Trust.sol";

/**
 * @title IdRegistry
 * @author Lifeworld
 */
contract IdRegistry is IIdRegistry, EIP712, Signatures, Nonces, Trust, Pausable {
    ////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////

    // string public constant NAME = "River ID";

    // string public constant VERSION = "2024.01.24";

    bytes32 public constant REGISTER_TYPEHASH =
        keccak256("Register(address to,address recovery,uint256 nonce,uint256 deadline)");          

    bytes32 public constant TRANSFER_TYPEHASH =
        keccak256("Transfer(uint256 rid,address to,uint256 nonce,uint256 deadline)");

    bytes32 public constant TRANSFER_AND_CHANGE_RECOVERY_TYPEHASH =
        keccak256("TransferAndChangeRecovery(uint256 rid,address to,address recovery,uint256 nonce,uint256 deadline)");

    bytes32 public constant CHANGE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("ChangeRecoveryAddress(uint256 rid,address from,address to,uint256 nonce,uint256 deadline)");

    ////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////

    uint256 public idCounter;
    mapping(address owner => uint256 rid) public idOf;
    mapping(uint256 rid => address owner) public custodyOf;
    mapping(uint256 rid => address recovery) public recoveryOf;

    ////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Set the owner of the contract to the provided _owner.
     *
     * @param _initialOwner Initial owner address.
     *
     */
    // solhint-disable-next-line no-empty-blocks
    constructor(address _initialOwner) Trust(_initialOwner) EIP712("River IdRegistry", "1") {}

    ////////////////////////////////////////////////////////////////
    // REGISTER
    ////////////////////////////////////////////////////////////////

    function register(address recovery) external returns (uint256 rid) {
        return _register(msg.sender, recovery);
    }

    function registerFor(
        address to, 
        address recovery, 
        uint256 deadline, 
        bytes calldata sig
    ) external trust returns (uint256 rid) {
        // Revert if signature is invalid
        _verifyRegisterSig({to: to, recovery: recovery, deadline: deadline, sig: sig});
        return _register(to, recovery);
    }

    // NOTE: will revert if msg.sender != Trust.trustedCaller
    function _register(address to, address recovery) internal returns (uint256 rid) {
        rid = _unsafeRegister(to, recovery);
        emit Register(to, idCounter, recovery);
    }

    // NOTE: will revert if contract is PAUSED
    function _unsafeRegister(address to, address recovery) internal whenNotPaused returns (uint256 rid) {
        /* Revert if the target(to) has an rid */
        if (idOf[to] != 0) revert Has_Id();
        /* Incrementing before assignment ensures that no one gets the 0 rid. */
        rid = ++idCounter;
        /* Register id */
        idOf[to] = rid;
        custodyOf[rid] = to;
        recoveryOf[rid] = recovery;
    }

    ////////////////////////////////////////////////////////////////
    // TRANSFER
    ////////////////////////////////////////////////////////////////

    // TODO:

    ////////////////////////////////////////////////////////////////
    // PERMISSIONED ACTIONS
    ////////////////////////////////////////////////////////////////

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    ////////////////////////////////////////////////////////////////
    // SIGNATURE VERIFICATION HELPERS
    ////////////////////////////////////////////////////////////////

    function _verifyRegisterSig(address to, address recovery, uint256 deadline, bytes memory sig) internal {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(REGISTER_TYPEHASH, to, recovery, _useNonce(to), deadline))),
            to,
            deadline,
            sig
        );
    }    
}
