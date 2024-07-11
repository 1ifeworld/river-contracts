// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {IdRegistry} from "../../src/IdRegistry.sol";
import {IIdRegistry} from "../../src/interfaces/IIdRegistry.sol";
import {KeyRegistry} from "../../src/KeyRegistry.sol";
import {IKeyRegistry} from "../../src/interfaces/IKeyRegistry.sol";
import {SignedKeyRequestValidator} from "../../src/validators/SignedKeyRequestValidator.sol";
import {IMetadataValidator} from "../../src/interfaces/IMetadataValidator.sol";
import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";

contract SignedKeyRequestValidatorTest is Test, TestSuiteSetup {       

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////       

    bytes EDDSA_PUB_KEY = 
        hex"b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f25e5f92444cde";

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////   

    /* contracts + accounts */
    IdRegistry public idRegistry;
    KeyRegistry public keyRegistry;
    SignedKeyRequestValidator public validator;
    CoinbaseSmartWalletFactory smartWalletFactory;
    CoinbaseSmartWallet smartWallet;
    bytes[] owners;
    uint256 nonce;

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////   

    // Set-up called before each test
    function setUp() public {   
        // setup fork
        uint256 baseSepoliaFork = vm.createFork('https://sepolia.base.org');
        vm.selectFork(baseSepoliaFork);
        smartWalletFactory = CoinbaseSmartWalletFactory(0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a);       
        // variavles
        nonce = 0;
        owners.push(abi.encode(user.addr));
        owners.push(abi.encode(trusted.addr));
        owners.push(passkeyOwner);
        smartWallet = smartWalletFactory.createAccount(owners, nonce);
        // trusted caller variable setup
        address[] memory trustedCallers = new address[](1);
        trustedCallers[0] = trusted.addr;
        bool[] memory statuses = new bool[](1);
        statuses[0] = true;        
        // deploy + setup id + key registry + metadata validator        
        vm.startPrank(trusted.addr);
        idRegistry = new IdRegistry(trusted.addr);  
        keyRegistry = new KeyRegistry(address(idRegistry), trusted.addr, 500);
        idRegistry.setTrustedCallers(trustedCallers, statuses);
        keyRegistry.setTrustedCallers(trustedCallers, statuses);
        validator = new SignedKeyRequestValidator(address(idRegistry), trusted.addr);
        keyRegistry.setValidator(1, 1, IMetadataValidator(validator));
        vm.stopPrank();    
    }    

    //////////////////////////////////////////////////
    // SETUP TESTS
    //////////////////////////////////////////////////        

    function testInitialIdRegistry() public {
        assertEq(address(validator.idRegistry()), address(idRegistry));
    }    

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////   

    function test_validate() public {
        uint256 deadline = _deadline();
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // generate registerfor signature
        bytes memory sig = _signRegister(
            user.key,
            user.addr,
            trusted.addr,
            deadline
        );
        // register id
        uint256 rid = idRegistry.registerFor(user.addr, trusted.addr, _deadline(), sig);        
        // get signature for signedKeyRequestBytes 
        bytes memory signedMetadata = _signMetadata(user.key, rid, EDDSA_PUB_KEY, deadline);
        // format signedKeyRequestBytes
        bytes memory signedKeyRequestBytes = _formatSignedKeyRequestBytes(rid, user.addr, signedMetadata, deadline);
        // call validator 
        bool response = validator.validate(
            0,
            EDDSA_PUB_KEY,
            signedKeyRequestBytes
        );
        assertEq(response, true);
    }


    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////   

    function _signRegister(
        uint256 pk,
        address to,
        address recovery,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        address signer = vm.addr(pk);
        bytes32 digest = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), to, recovery, idRegistry.nonces(signer), deadline))
        );
        signature = _sign(pk, digest);
    }             

    function _signMetadata(
        uint256 pk,
        uint256 requestingFid,
        bytes memory signerPubKey,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = validator.hashTypedDataV4(
            keccak256(abi.encode(validator.METADATA_TYPEHASH(), requestingFid, keccak256(signerPubKey), deadline))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);
    }    

    function _formatSignedKeyRequestBytes(uint256 requestRid, address requestSigner, bytes memory signature, uint256 deadline) internal view returns (bytes memory) {
        SignedKeyRequestValidator.SignedKeyRequestMetadata memory metadata = SignedKeyRequestValidator.SignedKeyRequestMetadata({
            requestRid: requestRid,
            requestSigner: requestSigner,
            signature: signature,
            deadline: deadline
        });
        return abi.encode(metadata); 
    }

    // function _prepareAddKeyEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, uint256 deadline) public view returns (bytes memory) {
    //     // bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //     //     keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     // );        

    //     // set up signed key request validator metadata signature


    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     );        
    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    //     bytes memory encodedWrapper = abi.encode(wrapper);



    //     SignedKeyRequestValidator.SignedKeyRequestMetadata memory metadata = SignedKeyRequestValidator({
    //         requestRid: 1,
    //         requestSigner: address(_smartWallet),
    //         signature: ,
    //         deadline: deadline
    //     })

    //     // set up key registry signature


    //     bytes32 keyRegistryAddForHash = keyRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(
    //             keyRegistry.ADD_TYPEHASH(), // typehash
    //             address(_smartWallet),      // rid woner
    //             1,                          // key type
    //             keccak256(EDDSA_PUB_KEY),   // key hash
    //             1,                          // key metadata type
    //             idRegistry.nonces(address(_smartWallet)), 
    //             deadline
    //         )
    //     )
    //     );                


    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    //     bytes memory encodedWrapper = abi.encode(wrapper);
    //     return encodedWrapper;                
    // }     



}
