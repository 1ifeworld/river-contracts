// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {IdRegistry} from "../../src/IdRegistry.sol";
import {IIdRegistry} from "../../src/interfaces/IIdRegistry.sol";
import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";
import "./IdRegistryTestSuite.sol";

contract IdRegistryTest is IdRegistryTestSuite {       

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

    function test_smartAccountPasskeySigner_registerFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);
        // get deadline
        uint256 deadline = _deadline();
        // generate registerFor signature for passkeySigner on smart wallet
        bytes memory sig = _preparePasskeySigForSmartWallet(smartWallet, recovery.addr, deadline);
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

    function test_erc6492_smartAccountEoaSigner_registerFor() public {
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // get deadline
        uint256 deadline = _deadline();
        // generate registerFor signature for eoaSigner on smart wallet
        (address undeployedSmartWallet, bytes memory sig) = _prepareEoa6492SigForSmartWallet(user, owners, recovery.addr, deadline);
        // Set up event tests
        vm.expectEmit(true, false, false, false, address(idRegistry));    
        // Emit event with expected value
        emit IIdRegistry.Register(address(undeployedSmartWallet), 1, recovery.addr);            
        // register id to user
        uint256 rid = idRegistry.registerFor(address(undeployedSmartWallet), recovery.addr, deadline, sig);
        vm.stopPrank();
        // asserts
        assertEq(idRegistry.idCounter(), rid);
        assertEq(idRegistry.idOf(address(undeployedSmartWallet)), rid);
        assertEq(idRegistry.custodyOf(rid), address(undeployedSmartWallet));
        assertEq(idRegistry.recoveryOf(rid), recovery.addr);
    }    

    function test_erc6492_smartAccountPasskeySigner_registerFor() public {
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // get deadline
        uint256 deadline = _deadline();
        // generate registerFor signature for eoaSigner on smart wallet
        (address undeployedSmartWallet, bytes memory sig) = _preparePasskey6492SigForSmartWallet(owners, recovery.addr, deadline);
        // Set up event tests
        vm.expectEmit(true, false, false, false, address(idRegistry));    
        // Emit event with expected value
        emit IIdRegistry.Register(address(undeployedSmartWallet), 1, recovery.addr);            
        // register id to user
        uint256 rid = idRegistry.registerFor(address(undeployedSmartWallet), recovery.addr, deadline, sig);
        vm.stopPrank();
        // asserts
        assertEq(idRegistry.idCounter(), rid);
        assertEq(idRegistry.idOf(address(undeployedSmartWallet)), rid);
        assertEq(idRegistry.custodyOf(rid), address(undeployedSmartWallet));
        assertEq(idRegistry.recoveryOf(rid), recovery.addr);
    }   
}