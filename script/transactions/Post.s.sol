// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {PostGateway} from "../../src/PostGateway.sol";
import {IPostGateway} from "../../src/interfaces/IPostGateway.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "openzeppelin-contracts/utils/cryptography/MessageHashUtils.sol";

contract PostScript is Script {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // anvil
    PostGateway postGateway = PostGateway(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0); 
    
    Account public relayer;
    Account public user;    
    uint256 public deployerPrivateKey;
    VmSafe.Wallet public deployerWallet;
    
    function setUp() public {
        relayer = makeAccount("relayer");
        user = makeAccount("user");              
    }

    function run() public {
        /* Load private key */
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        deployerPrivateKey = uint256(privateKeyBytes);
        deployerWallet = vm.createWallet(deployerPrivateKey);
        /* Start function transmission */
        vm.startBroadcast(deployerPrivateKey);

        // createChannel();        
        createItemAndAddToChannel();

        vm.stopBroadcast();
        /* End function transmission */
    }

    function createChannel() public {
        // structure init + data + message
        uint256[] memory admins = new uint256[](1);
        uint256[] memory members = new uint256[](0);
        admins[0] = 1;
        // members[0] = 2;
        // members[1] = 3;
        IPostGateway.Channel memory channel = IPostGateway.Channel({
            data: IPostGateway.ChannelData({
                dataType: IPostGateway.ChannelDataTypes.NAME_AND_DESC,
                contents: abi.encode("omRuYW1la2NoYW5uZWxOYW1la2Rlc2NyaXB0aW9ucmNoYW5uZWxEZXNjcmlwdGlvbg")
            }),
            access: IPostGateway.ChannelAccess({
                accessType: IPostGateway.ChannelAccessTypes.ROLES,
                contents: abi.encode(admins, members)
            })
        });
        bytes memory encodedChannel = abi.encode(channel);
        // structure Message
        IPostGateway.Message memory message = IPostGateway.Message({
            rid: 1,
            timestamp: 1706853740,
            msgType: IPostGateway.MessageTypes.CREATE_CHANNEL, // create/init id
            msgBody: encodedChannel
        });
        // create hash + sig for post
        (bytes32 createChannelHash, bytes memory createChannelSig) = signMessage(deployerPrivateKey, message);
        // structure Post
        IPostGateway.Post memory post = IPostGateway.Post({
            signer: deployerWallet.addr,
            message: message,
            hashType: 1,
            hash: createChannelHash, 
            sigType: 1,
            sig: createChannelSig
        });
        // console2.logBytes(post);
        // process post 
        postGateway.post(post);
    
    }

    function createItemAndAddToChannel() public {

        /*
            CREATE ITEM SETUP
        */

        // structure create item data/access + message
        uint256[] memory admins = new uint256[](1);
        admins[0] = 1;
        IPostGateway.Item memory createItem = IPostGateway.Item({
            data: IPostGateway.ItemData({
                dataType: IPostGateway.ItemDataTypes.STRING_URI,
                contents: abi.encode("bafkreig6fmbdm7cacbislqditpxjkhadzdlcuwr3ujqhsj4e7hjrbxxnaa")
            }),
            access: IPostGateway.ItemAccess({
                accessType: IPostGateway.ItemAccessTypes.ROLES,
                contents: abi.encode(admins)
            })
        });
        // structure create item Message
        IPostGateway.Message memory createItemMessage = IPostGateway.Message({
            rid: 1,
            timestamp: 1706853940,
            msgType: IPostGateway.MessageTypes.CREATE_ITEM,
            msgBody: abi.encode(createItem)
        });
        // create hash + sig for post
        (bytes32 createItemHash, bytes memory createItemSig) = signMessage(deployerPrivateKey, createItemMessage);
        // structure create item Post
        IPostGateway.Post memory createItemPost = IPostGateway.Post({
            signer: deployerWallet.addr,
            message: createItemMessage,
            hashType: 1,
            hash: createItemHash, 
            sigType: 1,
            sig: createItemSig
        });

        /*
            ADD ITEM SETUP
        */

        // structure ADD_ITEM_TO_CHANNEL  data/access + message
        IPostGateway.AddItem memory addItem = IPostGateway.AddItem({
            itemCid: "bafyreig36f4vknxpfqtli3hegy24a4z56zehylfpbdbr74zgi645uw6xua",
            channelCid: "bafyreiajeyzvo3vc3zgonbguqapeiz2o662w5al6av5ror6g2yvhafrn4m"
        });
        // structure add item Message
        IPostGateway.Message memory addItemMessage = IPostGateway.Message({
            rid: 1,
            timestamp: 1706853940,
            msgType: IPostGateway.MessageTypes.ADD_ITEM_TO_CHANNEL,
            msgBody: abi.encode(addItem)
        });
        // create hash + sig for post
        (bytes32 addItemHash, bytes memory addItemSig) = signMessage(deployerPrivateKey, addItemMessage);
        // structure add item Post
        IPostGateway.Post memory addItemPost = IPostGateway.Post({
            signer: deployerWallet.addr,
            message: addItemMessage,
            hashType: 1,
            hash: addItemHash, 
            sigType: 1,
            sig: addItemSig
        });
        //  setup batch post
        IPostGateway.Post[] memory batchPostInputs = new IPostGateway.Post[](1);
        // batchPostInputs[0] = createItemPost;
        batchPostInputs[0] = addItemPost;
        // process batch post 
        postGateway.postBatch(batchPostInputs);
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////  


    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        sig = abi.encodePacked(r, s, v);
    }  

    function signMessage(
        uint256 privateKey, 
        PostGateway.Message memory message
    ) public pure returns (bytes32 hash, bytes memory signedMessage) {
        hash = keccak256(abi.encode(message)).toEthSignedMessageHash();
        signedMessage = _sign(privateKey, hash);
    }           
}

// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/transactions/Post.s.sol:PostScript -vvvv --fork-url http://localhost:8545 --broadcast