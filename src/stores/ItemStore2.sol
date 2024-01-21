// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

// import "sstore2/SSTORE2.sol";
// import "solidity-bytes-utils/BytesLib.sol";
// import {IdRegistry} from "../IdRegistry.sol";
// import {DelegateRegistry} from "../DelegateRegistry.sol";
// import {ChannelStore} from "./ChannelStore.sol";
// import {Auth} from "../abstract/Auth.sol";
// import {IRenderer} from "../interfaces/IRenderer.sol";
// import {IStore} from "../interfaces/IStore.sol";
// import {IChannelLogic} from "../interfaces/IChannelLogic.sol";
// import {IChannelStore} from "../interfaces/IChannelStore.sol";
// import {River} from "../River.sol";

// contract ItemStore2 is Auth {

//     //////////////////////////////////////////////////
//     // TYPES
//     //////////////////////////////////////////////////

//     struct Channel {
//         address origin;
//         bytes32 uid;
//         bytes data;
//     }    
    
//     //////////////////////////////////////////////////
//     // ERRORS
//     //////////////////////////////////////////////////

//     error OnlyAdmin();
//     error No_Add_Access();
//     error No_Remove_Access();

//     //////////////////////////////////////////////////
//     // EVENTS
//     //////////////////////////////////////////////////

//     event Initialize(address origin, uint256 userId, bytes32 itemUid, address pointer);
//     event Data(address origin, uint256 userId, bytes32 itemUid, address pointer);
//     event Admin(address origin, uint256 userId, bytes32 itemUid, uint256 admin);
//     // event Add(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
//     event Remove(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
//     event Add(address sender, address origin, uint256 userId, bytes32 itemUid, address channelStore, uint256 channelOrigin, bytes32 channelUid);

//     //////////////////////////////////////////////////
//     // STORAGE
//     //////////////////////////////////////////////////

//     River public river;
//     IdRegistry public idRegistry;
//     DelegateRegistry public delegateRegistry;
//     mapping(address origin => mapping(bytes32 item => address pointer)) public dataForItem;    
//     mapping(address origin => mapping(bytes32 item => uint256 admin)) public adminForItem; 
//     mapping(address origin => mapping(bytes32 itemUid => mapping(uint256 userId => bool status))) public isAdminForItem;
//     mapping(bytes32 itemUid => mapping(bytes32 channelUid => uint256 userId)) addedItemToChannel;

//     //////////////////////////////////////////////////
//     // CONSTRUCTOR
//     //////////////////////////////////////////////////

//     constructor(address _river, address _idRegistry, address _delegateRegistry) {
//         river = River(_river);
//         idRegistry = IdRegistry(_idRegistry);
//         delegateRegistry = DelegateRegistry(_delegateRegistry);
//     }    

//     //
//     function initializeWithData(uint256 userId, bytes32 uid, bytes calldata data) external {
//         // Cache msg.sender
//         address sender = msg.sender;
//         // Decode incoming data
//         (
//             bytes memory itemData,
//             bytes32 channelUid
//         ) = abi.decode(data, (bytes, bytes32));
//         // Store item data2
//         address pointer = dataForItem[sender][uid] = SSTORE2.write(itemData);
//         // Set item admin
//         // NOTE: will want to filter out add events where the sender is River.sol to prevent spam
//         isAdminForItem[sender][uid][userId] = true;
//         // Initialize item
//         emit Initialize(sender, userId, uid, pointer);    
//         // Process adds
//         if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();     








//         // // Process adds
//         // for (uint256 i; i < channels.length; ++i) {
//         //     // Check user for add access + process add
//         //     _unsafeAdd(userId, uid, channel);
//         // }
//     }


//     function add(uint256 userId, bytes32 itemUid, Channel memory channel) {
//         // Check userId authorization for msg.sender
//         address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);     
//         // Check user for add access + process add
//         _unsafeAdd(userId, origin, itemUid, channel);
//     }

//     // needs to look up the store for the channel uid from river?
//     //      or is this something to just pass in directly
//     //      i think it has to be the river one? so uk that its always
//     //      the up to date store (instead of targeting an old store?)
//     function _unsafeAdd(
//         uint256 userId,     
//         bytes32 itemUid,
//         Channel memory channel        
//     ) internal {
//         // Get store for channel
//         address store = river.storeForUid(channel.store);
//         // Check for access 
//         if (!IChannelStore(store).getAddAccess(
//             userId, 
//             channel.origin, 
//             channel.uid, 
//             channel.data
//         )) revert No_Add_Access();
//         // Add item to channel
//         addedItemToChannel[origin][itemUid][channel.uid] = userId;
//         // Emit for indexing
//         emit Add(origin, userId, itemUid, channel.store, channel.origin, channel.uid);
//     }

//     // function _unsafeAdd(
//     //     address sender, 
//     //     uint256 userId, 
//     //     Channel memory channel
//     // ) internal {
//     //     if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();        
//     //     addedItemToChannel[itemHash][channelHash] = userId;
//     //     emit Add(sender, userId, itemHash, channelHash);
//     // }           
// }