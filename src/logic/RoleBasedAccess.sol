// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";
import {EIP712} from "../abstract/EIP712.sol";
import {Auth} from "../abstract/Auth.sol";
import {Signatures} from "../abstract/Signatures.sol";
import {IRoles} from "../interfaces/IRoles.sol";

/**
 * @title RoleBasedAccess
 * @author Lifeworld
 */
contract RoleBasedAccess is EIP712, Signatures, Auth, IRoles {
    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error Input_Length_Mismatch();
    error Only_Admin();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    event RolesSet(address sender, uint256 userId, uint256[] targetUserIds, bytes32 channelHash, Roles[] roles);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    mapping(address origin => mapping(bytes32 channelHash => mapping(uint256 userId => Roles))) public userRoleForChannel;

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////

    constructor(address _idRegistry, address _delegateRegistry) EIP712("RoleBasedAccess", "1") {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////

    function initializeWithData(uint256 userId, bytes32 channelHash, bytes memory data) external {
        // Cache msg.sender
        address sender = msg.sender;
        // Decode incoming data
        (uint256[] memory targetUserIds, Roles[] memory roles) = abi.decode(data, (uint256[], Roles[]));
        // Check for valid inputs
        if (targetUserIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < targetUserIds.length; ++i) {
            userRoleForChannel[sender][channelHash][targetUserIds[i]] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, userId, targetUserIds, channelHash, roles);
    }

    // NOTE: have weird thing where you need to specify target since initializeWithData route
    //       means setting that as base variable for mapping
    function editRoles(
        uint256 userId,
        address origin,
        uint256[] memory targetUserIds,
        bytes32 channelHash,
        Roles[] memory roles
    ) external {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(
            idRegistry, delegateRegistry, userId, msg.sender, address(this), this.editRoles.selector
        );
        // Check for valid inputs
        if (targetUserIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < targetUserIds.length; ++i) {
            if (userRoleForChannel[origin][channelHash][targetUserIds[i]] < Roles.ADMIN) revert Only_Admin();
            userRoleForChannel[origin][channelHash][targetUserIds[i]] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, userId, targetUserIds, channelHash, roles);
    }


    bytes32 public constant EDIT_ROLES_TYPEHASH =
        keccak256("EditRoles(uint256 userId,address origin,uint256[] targetUserIds,bytes32 channnelHash,Roles[] roles,uint256 deadline)");

        
    // // NOTE: have weird thing where you need to specify target since initializeWithData route
    // //       means setting that as base variable for mapping
    // function editRolesFor(
    //     uint256 userId,
    //     address origin,
    //     uint256[] memory targetUserIds,
    //     bytes32 channelHash,
    //     Roles[] memory roles,
    //     address signer,
    //     uint256 deadline,
    //     bytes calldata sig
    // ) external {
    //     // Verify valid transaction being generated on behalf of signer
    //     _verifyEditRolesSig(userId, origin, targetUserIds, channelHash, roles, signer, deadline, sig);        
    //     // Check authorization status for signer
    //     address authorizedSigner = 
    //         _authorizationCheck(idRegistry, delegateRegistry, userId, signer, address(this), this.editRoles.selector);
    //     // Check for valid inputs
    //     if (targetUserIds.length != roles.length) revert Input_Length_Mismatch();
    //     // Set roles
    //     for (uint256 i; i < targetUserIds.length; ++i) {
    //         if (userRoleForChannel[origin][channelHash][targetUserIds[i]] < Roles.ADMIN) revert Only_Admin();
    //         userRoleForChannel[origin][channelHash][targetUserIds[i]] = roles[i];
    //     }
    //     // Emit for indexing
    //     emit RolesSet(authorizedSigner, userId, targetUserIds, channelHash, roles);
    // }        

    // function _verifyEditRolesSig(         
    //     uint256 userId, 
    //     address origin,
    //     uint256[] memory targetUserIds,
    //     bytes32 channelHash,
    //     Roles[] memory roles,
    //     address signer,
    //     uint256 deadline, 
    //     bytes memory sig
    // ) internal view {
    //     _verifySig(
    //         _hashTypedDataV4(keccak256(abi.encode(
    //             EDIT_ROLES_TYPEHASH, 
    //             userId, 
    //             origin,
    //             targetUserIds,
    //             channelHash,
    //             roles, 
    //             deadline
    //         ))),
    //         signer,
    //         deadline,
    //         sig
    //     );
    // }       


    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    // NOTE: Uses role based access for all `access` returns
    function access(uint256 userId, bytes32 channelId, uint256 /*access*/) external view returns (uint256) {
        return uint256(userRoleForChannel[msg.sender][channelId][userId]);
    }

    // NOTE: Uses role based access for all `access` returns
    function getAccess(address target, uint256 userId, bytes32 channelId, uint256 /*access*/)
        external
        view
        returns (uint256)
    {
        return uint256(userRoleForChannel[target][channelId][userId]);
    }
}
