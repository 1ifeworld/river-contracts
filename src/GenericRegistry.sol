// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";

/**
 * @title GenericRegistry
 * @author Lifeworld
 */
contract GenericRegistry is Auth {
    struct Update {
        bytes32 uid;
        bytes data;
    }

    error Invalid_Uid();

    event NewUid(address sender, uint256 userId, bytes32 uid, address initPtr);
    event RequestUidUpdate(address sender, uint256 userId, bytes32 uid, bytes update);

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    uint256 public uidCount; // maybe want to make this user specific for ddos?
    mapping(bytes32 uid => address initPtr) public initForUid;
    mapping(bytes32 uid => uint256 userId) public creatorForUid;

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    function newUids(uint256 userId, bytes[] calldata inits)
        external
        returns (bytes32[] memory uids, address[] memory pointers)
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // increment global uid count
        uint256 count = ++uidCount;
        // Create uids
        for (uint256 i; i < inits.length; ++i) {
            uids[i] = keccak256(abi.encodePacked(userId, count));
            // set uid created by
            creatorForUid[uids[i]] = userId;
            // set init data for uid
            pointers[i] = initForUid[uids[i]] = SSTORE2.write(inits[i]);
            // Emit for indexing
            emit NewUid(sender, userId, uids[i], pointers[i]);
        }
    }

    function updateUids(uint256 userId, Update[] calldata updates) external {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Update uids
        for (uint256 i; i < updates.length; ++i) {
            if (creatorForUid[updates[i].uid] == 0) revert Invalid_Uid();
            emit RequestUidUpdate(sender, userId, updates[i].uid, updates[i].data);
        }
    }

    function getInitDataForUid(bytes32 uid) external view returns (bytes memory initData) {
        initData = SSTORE2.read(initForUid[uid]);
    }
}

/*
    This protocol aims to do the following things
    - provide an evm state based approach to creating + verifying unique identifiers
    - provide a gateway for targeting unique identifiers to issue updates
    - integrate both create/update paths with a dedicated id/delegate systems

    This allows for
    - state based agreement on uid creation time/origin/data
    - offchain processsing for updates post uid creation

    Example of a schema

    Channel Entity

    - create channel uid
        - uidRegistry.newUids({
            userId: 1,
            inits: [
                abi.encodePacked(
                    bytes8(uint64 uidType).                 // EX: 1 = Channel_v1
                    abi.encodePacked(              
                        abi.encodePacked(
                            bytes2(uint16 msgType),         // EX: 100 = Channel_v1_DataInitType_v1
                            abi.encode(string memory uri)   // EX: "ipfs://aosjdflad93012mnsdfopas02"
                        ),           
                        abi.encodePacked(
                            bytes2(uint16 msgType),         // EX: 200 = Channel_v1_AccessType_v1
                            abi.encode(
                                uin256[] admins,            // EX: [1]
                                uint256[] members           // EX: [2, 3]
                            )
                        )
                    )
                )
            )
        })

    - update channel uri
        - uidRegistry.updateUids({
            userId: 1,
            updates: [
                {
                    uid: keccak256("MOCK_SALT"),
                    data: abi.encodePacked(
                        bytes2(uint16) msgType,             // EX: 101 = Channel_v1_ChannelUpdateType_v1
                        abi.encode(string memory uri)       // EX: "ipfs://aosjdflad93012mnsdfopas02"
                    )
                }
            ]
        })    

    Note on updates:

    Updates would be processed according to an offchain processing logic defined in an arbitrary schema. 
    The benefits of this approach is that there is a globally agreeable state of uids that can be used
    across protocols, while the init pattern provides data anchors that can then be built on top of
    by subsequent update calls
*/