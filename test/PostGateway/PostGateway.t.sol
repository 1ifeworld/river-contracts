// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";

import {PostGateway} from "../../src/PostGateway.sol";
import {IPostGateway} from "../../src/interfaces/IPostGateway.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "openzeppelin-contracts/utils/cryptography/MessageHashUtils.sol";

contract PostGatewayTest is Test {       
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
  

    //////////////////////////////////////////////////
    // PARAMETERS
    //////////////////////////////////////////////////   

    PostGateway public postGateway;
    Account public relayer;
    Account public user;     

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////   

    // Set-up called before each test
    function setUp() public {
        postGateway = new PostGateway();          
        relayer = makeAccount("relayer");
        user = makeAccount("user");
    }    

    //////////////////////////////////////////////////
    // POST MESSAGE TESTS
    //////////////////////////////////////////////////  

    function test_post() public {

        /*
            CREATE Channel SETUP
        */

        // structure create channel data/access + message
        uint256[] memory admins = new uint256[](1);
        uint256[] memory members = new uint256[](2);
        admins[0] = 1;
        members[0] = 2;
        members[1] = 3;
        IPostGateway.Channel memory createChannel = IPostGateway.Channel({
            data: IPostGateway.ChannelData({
                dataType: IPostGateway.ChannelDataTypes.NAME_AND_DESC,
                contents: abi.encode("ipfs://contentsOfChannelUri")
            }),
            access: IPostGateway.ChannelAccess({
                accessType: IPostGateway.ChannelAccessTypes.ROLES,
                contents: abi.encode(admins, members)
            })
        });
        // structure create channel Message
        IPostGateway.Message memory createChannelMessage = IPostGateway.Message({
            rid: 1,
            timestamp: block.timestamp + 1,
            msgType: IPostGateway.MessageTypes.CREATE_CHANNEL,
            msgBody: abi.encode(createChannel)
        });
        // create hash + sig for post
        bytes32 createChannelHash = keccak256(abi.encode(createChannelMessage)).toEthSignedMessageHash();
        bytes memory createChannelSig = signMessage(user.key, createChannelMessage);
        // structure create item Post
        IPostGateway.Post memory createChannelPost = IPostGateway.Post({
            signer: user.addr,
            message: createChannelMessage,
            hashType: 1,
            hash: createChannelHash, 
            sigType: 1,
            sig: createChannelSig
        });
        // process post 
        postGateway.post(createChannelPost);
        // run sig test
        assertEq(SignatureChecker.isValidSignatureNow(user.addr, createChannelHash, createChannelSig), true);             
    }

    // initial example is creating an item + posting it to a channel
    function test_batchPost() public {
        vm.startPrank(relayer.addr);

        /*
            CREATE ITEM SETUP
        */

        // structure create item data/access + message
        uint256[] memory admins = new uint256[](1);
        admins[0] = 1;
        IPostGateway.Item memory createItem = IPostGateway.Item({
            data: IPostGateway.ItemData({
                dataType: IPostGateway.ItemDataTypes.STRING_URI,
                contents: abi.encode("ipfs://contentsOf")
            }),
            access: IPostGateway.ItemAccess({
                accessType: IPostGateway.ItemAccessTypes.ROLES,
                contents: abi.encode(admins)
            })
        });
        // structure create item Message
        IPostGateway.Message memory createItemMessage = IPostGateway.Message({
            rid: 1,
            timestamp: block.timestamp + 1,
            msgType: IPostGateway.MessageTypes.CREATE_ITEM,
            msgBody: abi.encode(createItem)
        });
        // create hash + sig for post
        bytes32 createItemHash = keccak256(abi.encode(createItemMessage)).toEthSignedMessageHash();
        bytes memory createItemSig = signMessage(user.key, createItemMessage);
        // structure create item Post
        IPostGateway.Post memory createItemPost = IPostGateway.Post({
            signer: user.addr,
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
            itemCid: "ipfs://itemPlaceholder",
            channelCid: "ipfs://channelPlaceholder"
        });
        // structure add item Message
        IPostGateway.Message memory addItemMessage = IPostGateway.Message({
            rid: 1,
            timestamp: block.timestamp + 1,
            msgType: IPostGateway.MessageTypes.ADD_ITEM_TO_CHANNEL,
            msgBody: abi.encode(addItem)
        });
        // create hash + sig for post
        bytes32 addItemHash = keccak256(abi.encode(addItemMessage)).toEthSignedMessageHash();
        bytes memory addItemSig = signMessage(user.key, addItemMessage);
        // structure add item Post
        IPostGateway.Post memory addItemPost = IPostGateway.Post({
            signer: user.addr,
            message: addItemMessage,
            hashType: 1,
            hash: addItemHash, 
            sigType: 1,
            sig: addItemSig
        });
        //  setup batch post
        IPostGateway.Post[] memory batchPostInputs = new IPostGateway.Post[](2);
        batchPostInputs[0] = createItemPost;
        batchPostInputs[1] = addItemPost;
        // process post 
        postGateway.postBatch(batchPostInputs);
        // run sig test
        address check = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        bytes32 hashCheck = 0x414a0446bba1aeca4a44b20a2ad7dcb8824e46c07fcea0d9ac6b8bf7dcbf00bf;
        bytes memory sigCheck = hex"d4c0f1bb96941578f0370c69190ba4e11ad76dd23c2cd8f9e12c30f882f3ec5b6b9c64f1b60c210988ba86030a380d4ce51e2a1fe7db0ff163567aab927586d21b";
        // assertEq(SignatureChecker.isValidSignatureNow(user.addr, createItemHash, createItemSig), true);         
        // assertEq(SignatureChecker.isValidSignatureNow(user.addr, addItemHash, addItemSig), true);         
        assertEq(SignatureChecker.isValidSignatureNow(check, hashCheck, sigCheck), true);         
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////  


    function _sign(uint256 privateKey, bytes32 digest) internal returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        sig = abi.encodePacked(r, s, v);
        assertEq(sig.length, 65);
    }  

    function signMessage(
        uint256 privateKey, 
        IPostGateway.Message memory message
    ) public returns (bytes memory signedMessage) {
        bytes32 hash = keccak256(abi.encode(message)).toEthSignedMessageHash();
        signedMessage = _sign(privateKey, hash);
    }         
}