// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {IdRegistry} from "../../src/IdRegistry.sol";
import {IIdRegistry} from "../../src/interfaces/IIdRegistry.sol";

contract IdRegistryTest is Test, TestSuiteSetup {       

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////       

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////   

    /* contracts + accounts */
    IdRegistry public idRegistry;
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
        // id registry
        idRegistry = new IdRegistry(trusted.addr);  
        vm.prank(trusted.addr);
        idRegistry.setTrustedCaller(trusted.addr);
    }    

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////    

    function test_eoa_registerFor() public {
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // generate registerfor signature
        bytes memory sig = _signRegister(
            user.key,
            user.addr,
            trusted.addr,
            _deadline()
        );
        // Set up event tests
        vm.expectEmit(true, false, false, false, address(idRegistry));    
        // Emit event with expected value
        emit IIdRegistry.Register(user.addr, 1, trusted.addr);            
        // register id to user
        uint256 rid = idRegistry.registerFor(user.addr, trusted.addr, _deadline(), sig);
        vm.stopPrank();
        // asserts
        assertEq(idRegistry.idCounter(), rid);
        assertEq(idRegistry.idOf(user.addr), rid);
        assertEq(idRegistry.custodyOf(rid), user.addr);
        assertEq(idRegistry.recoveryOf(rid), trusted.addr);
    }

    function test_smartAccountEoaSigner_registerFor() public {
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // get deadline
        uint256 deadline = _deadline();
        // generate registerFor signature for eoaSigner on smart wallet
        bytes memory sig = _prepareEoaSigForSmartWallet(smartWallet, user, recovery.addr, deadline);
        // Set up event tests
        vm.expectEmit(true, false, false, false, address(idRegistry));    
        // Emit event with expected value
        emit IIdRegistry.Register(address(smartWallet), 1, recovery.addr);            
        // register id to user
        uint256 rid = idRegistry.registerFor(address(smartWallet), recovery.addr, deadline, sig);
        vm.stopPrank();
        // asserts
        assertEq(idRegistry.idCounter(), rid);
        assertEq(idRegistry.idOf(address(smartWallet)), rid);
        assertEq(idRegistry.custodyOf(rid), address(smartWallet));
        assertEq(idRegistry.recoveryOf(rid), recovery.addr);
    }


    // //////////////////////////////////////////////////
    // // HELPERS
    // //////////////////////////////////////////////////               


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

    function _prepareEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
        );        
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
        bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
        bytes memory encodedWrapper = abi.encode(wrapper);
        return encodedWrapper;                
    }        


    // function _prepareEoaSigForSmartAccount(CoinbaseSmartWallet account, Account memory eoaOwner) public view returns (bytes32, bytes memory) {
    //     bytes32 digest = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eea4;
    //     // NOTE: we aren't actually using the account contract here
    //     //       we are just accessing replaySafeHash from it
    //     // TODO: cleaner version of test would let us access replaySafeHash from a library or
    //     //       separately set function
    //     bytes32 toSign = account.replaySafeHash(digest);
    //     bytes memory eoaSigForOwner = _sign(eoaOwner.key, toSign);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner});
    //     bytes memory encodedWrapper = abi.encode(wrapper);
    //     return (digest, encodedWrapper);
    // }    
    
}
