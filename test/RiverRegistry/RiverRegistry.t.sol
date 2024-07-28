// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {RiverRegistry} from "../../src/RiverRegistry.sol";
import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";
import "./RiverRegistryTestSuite.sol";

contract RiverRegistryTest is RiverRegistryTestSuite {       

    /*
        WIP notes
        - 
    */

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                ID MIGRATION                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    //////////////////////////////////////////////////
    // TRUSTED PREP MIGRATION
    //////////////////////////////////////////////////        

    // invariants
    // - only trusted - X
    // - only for rids 1-200 - x 
    // - only if rid has not been migrated yet - X
    // - only if rid has been prepped - X
    // - only if recipient has no id - x    

    function test_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        _prepMigrateForAccounts(cutoff);

        assertEq(riverRegistry.idCount(), cutoff);
    }  

    function test_revertOnlyTrusted_prepMigrate() public {
        // start prank as untrusted caller
        vm.startPrank(malicious.addr);
        
        vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
        _prepMigrateForAccounts(1);
    }       

    function test_revertHasId_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        address randomAccount = randomishAccount(1);
        riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        vm.expectRevert(abi.encodeWithSignature("Has_Id()"));
        riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
    }       

    function test_revert_pastCutoff_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        address anotherRandomAccount = randomishAccount(cutoff + 1);
        vm.expectRevert(abi.encodeWithSignature("Past_Migration_Cutoff()"));
        riverRegistry.trustedPrepMigration(anotherRandomAccount, recovery.addr);
        assertEq(riverRegistry.idCount(), cutoff);
    }     

    //////////////////////////////////////////////////
    // TRUSTED MIGRATE FOR
    //////////////////////////////////////////////////     

    function test_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);
            address fromCustody = riverRegistry.custodyOf(i + 1);
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
            assertEq(riverRegistry.idOf(randomAccount2), i + 1);
            assertEq(riverRegistry.idOf(fromCustody), 0);
            assertEq(riverRegistry.custodyOf(i + 1), randomAccount2);
            assertEq(riverRegistry.recoveryOf(i + 1), recovery.addr);
            assertEq(riverRegistry.hasMigrated(i + 1), true);
        }        
    }   

    function test_revertOnlyTrusted_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        vm.stopPrank();
        vm.startPrank(malicious.addr);

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);
            vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);
        }        
    }       

    function test_revertOnlyToCutoff_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff + 1);    
        for (uint256 i; i < cutoff + 1; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);
            if (i == cutoff) {
                vm.expectRevert(abi.encodeWithSignature("Past_Migration_Cutoff()"));
                riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
            } else {
                riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
            }            
        }        
    }             

    function test_revertAlreadyMigrated_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        _prepMigrateForAccounts(cutoff);

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);            
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);
            address randomAccount3 = randomishAccount(cutoff + cutoff + i);        
            // try to migrate a second time for each one and fail
            vm.expectRevert(abi.encodeWithSignature("Already_Migrated()"));
            riverRegistry.trustedMigrateFor(i + 1, randomAccount3, recovery.addr, keyInits[i]);
        }        
    }   

    function test_revertHasNoId_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // not prepping migration for revert

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);            
            // vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
            vm.expectRevert(abi.encodeWithSignature("Has_No_Id()"));
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
        }        
    }       

    function test_revertHasId_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        // process 200 migrations and run tests
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);            

            if (i == cutoff - 1) {                
                address custodyToCheck = riverRegistry.custodyOf(i);
                // expert revert on 200th migration because trying to migrate to recipient of 199th migration that already has id now
                vm.expectRevert(abi.encodeWithSignature("Has_Id()"));
                riverRegistry.trustedMigrateFor(i + 1, custodyToCheck, recovery.addr, keyInits[i]);            
            } else {
                riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
            }          
        }        
    }        

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *               ID REGISTRATION                  *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    /*
        NOTES
        - `trustedRegisterFor` tests handle the testing of the 
          `_issueAndAdd()` function shared by all register txns,
          which includes checks for migration cutoff, pausing, and 
          custody/id invariants
        - `registerFor()` tests confirm RiverRegistry is compatible with 6492 signatures
           made with eoa/passkey signers from coinbase wallet factory. also tests that
           expired signatures will revert
    */ 

    //////////////////////////////////////////////////
    // TRUSTED REGISTER FOR
    ////////////////////////////////////////////////// 

    // invariants
    // - only trusted - X
    // - only for rids 201+ - X
    // - only if recipient has no id - X                 
    // - fails if paused - x    
    
    function test_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        uint256 issuedRid = riverRegistry.trustedRegisterFor(randomCustody, recovery.addr, keyInits[0]);
        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(randomCustody), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), randomCustody);
        assertEq(riverRegistry.hasMigrated(issuedRid), false);

        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, keyInits[0][0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.ADDED));
        assertEq(keyData.keyType, 1);
        bytes memory addedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.ADDED, 0);
        assertEq(addedKey, keyInits[0][0].key);
    }                

    function test_revertOnlyTrusted_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        vm.startPrank(malicious.addr);

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
        riverRegistry.trustedRegisterFor(randomCustody, recovery.addr, keyInits[0]);
    }        

    function test_revertBeforeMigrationCutoff_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF() - 1);

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Before_Migration_Cutoff()"));
        riverRegistry.trustedRegisterFor(randomCustody, recovery.addr, keyInits[0]);
    }         

    function test_revertHasId_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        // retrieve custody of rid 200
        address custodyOfRid200 = riverRegistry.custodyOf(200);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Has_Id()"));
        riverRegistry.trustedRegisterFor(custodyOfRid200, recovery.addr, keyInits[0]);
    }           

    function test_revertPaused_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        // pause contract
        riverRegistry.pause();
        assertEq(riverRegistry.paused(), true);

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);     

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.trustedRegisterFor(randomCustody, recovery.addr, keyInits[0]);
    }              

    //////////////////////////////////////////////////
    // REGISTER
    //////////////////////////////////////////////////       

    // invariants   
    // - only if allowance != 0 OR isPublic == true
    // - only if msg.value = price

    /* POSTIVE TESTS */

    function test_isPublic_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        uint256 issuedRid = riverRegistry.register(recovery.addr, keyInits[0]);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(user.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), user.addr);
    }      

    function test_hasAllowance_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // give allowance to user
        riverRegistry.increaseAllowance(user.addr, 1);
        assertEq(riverRegistry.allowanceOf(user.addr), 1);

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        uint256 issuedRid = riverRegistry.register(recovery.addr, keyInits[0]);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(user.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), user.addr);
        assertEq(riverRegistry.allowanceOf(user.addr), 0);
    }          

    function test_withPriceHasAllowance_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();        
        // update price and deal ether to user
        riverRegistry.setPrice(1 ether);
        vm.deal(user.addr, 1 ether);

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        uint256 issuedRid = riverRegistry.register{value: 1 ether}(recovery.addr, keyInits[0]);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(user.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), user.addr);
        assertEq(address(riverRegistry).balance, 1 ether);
    }         

    /* NEGATIVE TESTS */

    function test_revertNotAllowed_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // not setting registry to public, or giving user allowance for revert  

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Not_Allowed()"));
        riverRegistry.register(recovery.addr, keyInits[0]);
    }       

    function test_revertMsgValueIncorrect_hasAllowance_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // give allowance to user
        riverRegistry.increaseAllowance(user.addr, 1);
        // update price, deal to user
        riverRegistry.setPrice(1 ether);
        vm.deal(user.addr, 1.6 ether);

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Msg_Value_Incorrect()"));
        // send insufficient funds (under or over)
        riverRegistry.register{value: 0.5 ether}(recovery.addr, keyInits[0]);
        // expect revert again sending too MUCH ether
        vm.expectRevert(abi.encodeWithSignature("Msg_Value_Incorrect()"));
        riverRegistry.register{value: 1.1 ether}(recovery.addr, keyInits[0]);
    }     

    function test_revertMsgValueIncorrect_isPublic_register() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        // update price, deal to user
        riverRegistry.setPrice(1 ether);
        vm.deal(user.addr, 1.6 ether);

        vm.stopPrank();
        vm.startPrank(user.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        vm.expectRevert(abi.encodeWithSignature("Msg_Value_Incorrect()"));
        // send insufficient funds (under or over)
        riverRegistry.register{value: 0.5 ether}(recovery.addr, keyInits[0]);
        // expect revert again sending too MUCH ether
        vm.expectRevert(abi.encodeWithSignature("Msg_Value_Incorrect()"));
        riverRegistry.register{value: 1.1 ether}(recovery.addr, keyInits[0]);
    }         

    //////////////////////////////////////////////////
    // REGISTER FOR
    //////////////////////////////////////////////////      

    function test_isPublic_eoaRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // generate signature for user
        bytes memory sig = _signRegister(user.key, user.addr, recovery.addr, keyInits[0], _deadline());
        uint256 issuedRid = riverRegistry.registerFor(user.addr, recovery.addr, keyInits[0], _deadline(), sig);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(user.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), user.addr);
    }        

    function test_isPublic_smartWalletEoaSignerRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // deploy wallet, then generate signature for user
        smartWallet = smartWalletFactory.createAccount(owners, nonce); 
        assertGt(address(smartWallet).code.length, 0);
        bytes memory sig = _prepareEoaSigForSmartWallet(smartWallet, user, recovery.addr, keyInits[0], _deadline());
        uint256 issuedRid = riverRegistry.registerFor(address(smartWallet), recovery.addr, keyInits[0], _deadline(), sig);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(address(smartWallet)), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), address(smartWallet));
    }     

    function test_isPublic_undeployedSmartWalletEoaSignerRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // generate signature for user
        assertEq(address(smartWallet).code.length, 0);      
        (address undeployedSmartWallet, bytes memory sig) = _prepareEoa6492SigForSmartWallet(user, owners, recovery.addr, keyInits[0], _deadline());  
        uint256 issuedRid = riverRegistry.registerFor(undeployedSmartWallet, recovery.addr, keyInits[0], _deadline(), sig);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(undeployedSmartWallet), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), undeployedSmartWallet);
    }         

    function test_isPublic_smartWalletPasskeySignerRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // deploy wallet, then generate signature for user
        smartWallet = smartWalletFactory.createAccount(owners, nonce); 
        assertGt(address(smartWallet).code.length, 0);
        bytes memory sig = _preparePasskeySigForSmartWallet(smartWallet, recovery.addr, keyInits[0], _deadline());
        uint256 issuedRid = riverRegistry.registerFor(address(smartWallet), recovery.addr, keyInits[0], _deadline(), sig);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(address(smartWallet)), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), address(smartWallet));
    }    

    function test_isPublic_undeployedSmartWalletPasskeySignerRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // generate signature for user
        assertEq(address(smartWallet).code.length, 0);      
        (address undeployedSmartWallet, bytes memory sig) = _preparePasskey6492SigForSmartWallet(owners, recovery.addr, keyInits[0], _deadline()); 
        uint256 issuedRid = riverRegistry.registerFor(undeployedSmartWallet, recovery.addr, keyInits[0], _deadline(), sig);

        assertEq(riverRegistry.idCount(), 201);
        assertEq(riverRegistry.idOf(undeployedSmartWallet), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), undeployedSmartWallet);
    }        

    function test_revertInvalidSignature_isPublic_eoaRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // generate signature for user
        bytes memory sig = _signRegister(user.key, user.addr, recovery.addr, keyInits[0], _deadline());
        vm.expectRevert(abi.encodeWithSignature("Invalid_Signature()"));
        riverRegistry.registerFor(user.addr, recovery.addr, keyInits[0], _deadline(), bytes.concat(sig, new bytes(3)));
    }     

    function test_revertSignatureExpired_isPublic_eoaRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // set registry to public
        riverRegistry.toggleIsPublic();
        assertEq(riverRegistry.isPublic(), true);

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        // generate signature for user
        uint256 deadline = _deadline();
        bytes memory sig = _signRegister(user.key, user.addr, recovery.addr, keyInits[0], deadline);
        // jump into the future, so that block.timestamp > deadline, making signature expired
        vm.warp(deadline + 100);
        vm.expectRevert(abi.encodeWithSignature("Signature_Expired()"));
        riverRegistry.registerFor(user.addr, recovery.addr, keyInits[0], deadline, sig);
    }       

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 ID TRANSFERS                   *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    // invariants   
    // - only if contract isnt paused

    //////////////////////////////////////////////////
    // TRANSFER
    //////////////////////////////////////////////////      

    function test_transfer() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(user.addr);

        Account memory toCustody = makeAccount("transfer");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        riverRegistry.transfer(toCustody.addr, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }      

    function test_revertEnforcedPause_transfer() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        riverRegistry.pause();
        vm.stopPrank();
        vm.startPrank(user.addr);

        Account memory toCustody = makeAccount("transfer");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.transfer(toCustody.addr, _deadline(), toSig);
    }          

    //////////////////////////////////////////////////
    // TRANSFER FOR
    //////////////////////////////////////////////////        

    function test_sigTransferFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(relayer.addr);

        Account memory toCustody = makeAccount("transfer");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        bytes memory fromSig = _signTransfer(user.key, issuedRid, toCustody.addr, _deadline());
        riverRegistry.transferFor(user.addr, toCustody.addr, _deadline(), fromSig, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }       

    function test_revertEnforcedPause_transferFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        riverRegistry.pause();
        vm.stopPrank();
        vm.startPrank(relayer.addr);

        Account memory toCustody = makeAccount("transfer");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        bytes memory fromSig = _signTransfer(user.key, issuedRid, toCustody.addr, _deadline());
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.transferFor(user.addr, toCustody.addr, _deadline(), fromSig, _deadline(), toSig);        
    }               

    //////////////////////////////////////////////////
    // TRANSFER AND CHANGE RECOVERY
    //////////////////////////////////////////////////             
    
    function test_transferAndChangeRecovery() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(user.addr);

        Account memory toCustody = makeAccount("transfer");
        Account memory newRecovery = makeAccount("newRecovery");
        bytes memory toSig = _signTransferAndChangeRecovery(toCustody.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        riverRegistry.transferAndChangeRecovery(toCustody.addr, newRecovery.addr, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), newRecovery.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }      

    function test_revertEnforcedPause_transferAndChangeRecovery() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        riverRegistry.pause();
        vm.stopPrank();
        vm.startPrank(user.addr);

        Account memory toCustody = makeAccount("transfer");
        Account memory newRecovery = makeAccount("newRecovery");
        bytes memory toSig = _signTransferAndChangeRecovery(toCustody.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.transferAndChangeRecovery(toCustody.addr, newRecovery.addr, _deadline(), toSig);        
    }          


    function test_sigTransferAndChangeRecoveryFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(relayer.addr);

        Account memory toCustody = makeAccount("transfer");
        Account memory newRecovery = makeAccount("newRecovery");
        bytes memory toSig = _signTransferAndChangeRecovery(toCustody.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        bytes memory fromSig = _signTransferAndChangeRecovery(user.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        riverRegistry.transferAndChangeRecoveryFor(user.addr, toCustody.addr, newRecovery.addr, _deadline(), fromSig, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), newRecovery.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }       

    function test_revertEnforcedPause_sigTransferAndChangeRecoveryFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        riverRegistry.pause();
        vm.stopPrank();
        vm.startPrank(relayer.addr);

        Account memory toCustody = makeAccount("transfer");
        Account memory newRecovery = makeAccount("newRecovery");
        bytes memory toSig = _signTransferAndChangeRecovery(toCustody.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        bytes memory fromSig = _signTransferAndChangeRecovery(user.key, issuedRid, toCustody.addr, newRecovery.addr, _deadline());
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.transferAndChangeRecoveryFor(user.addr, toCustody.addr, newRecovery.addr, _deadline(), fromSig, _deadline(), toSig);        
    }         

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 ID RECOVERY                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */
    
    //////////////////////////////////////////////////
    // RECOVER
    //////////////////////////////////////////////////      

    function test_recover() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(recovery.addr);

        Account memory toCustody = makeAccount("recover");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        riverRegistry.recover(user.addr, toCustody.addr, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }          

    function test_revertNotRecovery_recover() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(malicious.addr);

        Account memory toCustody = makeAccount("recover");
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        riverRegistry.recover(user.addr, toCustody.addr, _deadline(), toSig);
    }          

    //////////////////////////////////////////////////
    // RECOVER FOR
    //////////////////////////////////////////////////  

   function test_sigRecoverFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(relayer.addr);

        Account memory toCustody = makeAccount("recover");
        bytes memory recoverySig = _signTransfer(recovery.key, issuedRid, toCustody.addr, _deadline());
        bytes memory toSig = _signTransfer(toCustody.key, issuedRid, toCustody.addr, _deadline());
        riverRegistry.recoverFor(user.addr, toCustody.addr, _deadline(), recoverySig, _deadline(), toSig);

        assertEq(riverRegistry.idOf(toCustody.addr), issuedRid);
        assertEq(riverRegistry.custodyOf(issuedRid), toCustody.addr);
        assertEq(riverRegistry.idOf(user.addr), 0);
    }                      

    //////////////////////////////////////////////////
    // CHANGE RECOVERY
    //////////////////////////////////////////////////          

    function test_changeRecovery() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(user.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), recovery.addr);
        Account memory newRecovery = makeAccount("newRecovery");
        riverRegistry.changeRecoveryAddress(newRecovery.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), newRecovery.addr);
    }               

    function test_revertHasNoId_changeRecovery() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(malicious.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), recovery.addr);
        Account memory newRecovery = makeAccount("newRecovery");
        vm.expectRevert(abi.encodeWithSignature("Has_No_Id()"));
        riverRegistry.changeRecoveryAddress(newRecovery.addr);
    }         

    function test_sigChangeRecoveryFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        // trusted register id to user address
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);        

        vm.stopPrank();
        vm.startPrank(relayer.addr);
        assertEq(riverRegistry.recoveryOf(issuedRid), recovery.addr);
        Account memory newRecovery = makeAccount("newRecovery");
        bytes memory ridOwnerSig = _signChangeRecoveryAddress(user.key, issuedRid, recovery.addr, newRecovery.addr, _deadline());
        riverRegistry.changeRecoveryAddressFor(user.addr, newRecovery.addr, _deadline(), ridOwnerSig);
        assertEq(riverRegistry.recoveryOf(issuedRid), newRecovery.addr);
    }          

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                  KEY ADD                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    // invariants
    // - cant add key if its not in null state
    // - cant add key when paused


    //////////////////////////////////////////////////
    // ADD
    //////////////////////////////////////////////////         

    function test_add() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);   

        vm.stopPrank();
        vm.startPrank(user.addr);                  
    
        IRiverRegistry.KeyInit[] memory addKeyInit = new IRiverRegistry.KeyInit[](1);
        addKeyInit[0] = IRiverRegistry.KeyInit({
            keyType: 1,
            key: abi.encode("addKeyInit")
        });
        riverRegistry.add(addKeyInit[0].keyType, addKeyInit[0].key);

        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, addKeyInit[0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.ADDED));
        assertEq(keyData.keyType, 1);
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.ADDED), 2);
        bytes memory addedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.ADDED, 1);
        assertEq(addedKey, addKeyInit[0].key);
    }        

    function test_revertUnauthorized_add() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);   

        vm.stopPrank();
        vm.startPrank(malicious.addr);                  
    
        IRiverRegistry.KeyInit[] memory addKeyInit = new IRiverRegistry.KeyInit[](1);
        addKeyInit[0] = IRiverRegistry.KeyInit({
            keyType: 1,
            key: abi.encode("addKeyInit")
        });
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        riverRegistry.add(addKeyInit[0].keyType, addKeyInit[0].key);
    }        

    function test_revertEnforcedPause_add() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);   

        riverRegistry.pause();
        vm.stopPrank();
        vm.startPrank(user.addr);                  
    
        IRiverRegistry.KeyInit[] memory addKeyInit = new IRiverRegistry.KeyInit[](1);
        addKeyInit[0] = IRiverRegistry.KeyInit({
            keyType: 1,
            key: abi.encode("addKeyInit")
        });
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        riverRegistry.add(addKeyInit[0].keyType, addKeyInit[0].key);
    }            

    //////////////////////////////////////////////////
    // ADD FOR
    //////////////////////////////////////////////////      

    function test_sigAddFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);

        vm.stopPrank();
        vm.startPrank(relayer.addr);          
    
        IRiverRegistry.KeyInit[] memory addKeyInit = new IRiverRegistry.KeyInit[](1);
        addKeyInit[0] = IRiverRegistry.KeyInit({
            keyType: 1,
            key: abi.encode("addKeyInit")
        });
        bytes memory addSig = _signAdd(user.key, user.addr, addKeyInit[0].keyType, addKeyInit[0].key, _deadline());
        riverRegistry.addFor(user.addr, addKeyInit[0].keyType, addKeyInit[0].key, _deadline(), addSig);

        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, addKeyInit[0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.ADDED));
        assertEq(keyData.keyType, 1);
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.ADDED), 2);
        bytes memory addedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.ADDED, 1);
        assertEq(addedKey, addKeyInit[0].key);
    }               

    //////////////////////////////////////////////////
    // TRUSTED ADD FOR 
    //////////////////////////////////////////////////                 

    function test_trustedAddFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(randomCustody, recovery.addr, keyInits[0]);
    
        IRiverRegistry.KeyInit[] memory addKeyInit = new IRiverRegistry.KeyInit[](1);
        addKeyInit[0] = IRiverRegistry.KeyInit({
            keyType: 1,
            key: abi.encode("addKeyInit")
        });
        riverRegistry.trustedAddFor(randomCustody, addKeyInit[0].keyType, addKeyInit[0].key);


        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, addKeyInit[0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.ADDED));
        assertEq(keyData.keyType, 1);
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.ADDED), 2);
        bytes memory addedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.ADDED, 1);
        assertEq(addedKey, addKeyInit[0].key);
    }           

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 KEY REMOVAL                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    //////////////////////////////////////////////////
    // REMOVE
    //////////////////////////////////////////////////         

    function test_remove() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);   

        vm.stopPrank();
        vm.startPrank(user.addr);                  

        riverRegistry.remove(keyInits[0][0].key);

        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, keyInits[0][0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.REMOVED));
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.REMOVED), 1);
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.ADDED), 0);
        bytes memory removedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.REMOVED, 0);
        assertEq(removedKey, keyInits[0][0].key);          
    }

    //////////////////////////////////////////////////
    // REMOVE FOR
    //////////////////////////////////////////////////   

    function test_sigRemoveFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // process prep migration
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]);   

        vm.stopPrank();
        vm.startPrank(relayer.addr);                  

        bytes memory removeSig = _signRemove(user.key, user.addr, keyInits[0][0].key, _deadline());
        riverRegistry.removeFor(user.addr, keyInits[0][0].key, _deadline(), removeSig);

        IRiverRegistry.KeyData memory keyData = riverRegistry.keyDataOf(issuedRid, keyInits[0][0].key);        
        assertEq(uint256(keyData.state), uint256(IRiverRegistry.KeyState.REMOVED));
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.REMOVED), 1);
        assertEq(riverRegistry.totalKeys(issuedRid, IRiverRegistry.KeyState.ADDED), 0);
        bytes memory removedKey = riverRegistry.keyAt(issuedRid, IRiverRegistry.KeyState.REMOVED, 0);
        assertEq(removedKey, keyInits[0][0].key);          
    }                        

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    VIEWS                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    //////////////////////////////////////////////////
    // IS VALID SIGNATURE
    //////////////////////////////////////////////////              

    function test_isValidSignature() public {
        // register rid to user
        vm.startPrank(trusted.addr);
        _prepMigrateForAccounts(riverRegistry.RID_MIGRATION_CUTOFF());
        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   
        uint256 issuedRid = riverRegistry.trustedRegisterFor(user.addr, recovery.addr, keyInits[0]); 

        // generate sig for user and request verification from reigstry
        bytes32 digest = keccak256("isValid");
        bytes memory sig = _sign(user.key, digest);
        bool isValid = riverRegistry.verifyRidSignature(user.addr, issuedRid, digest, sig);
        assertEq(isValid, true);
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                   BUSINESS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    function test_constructorArgs() public {
        assertEq(riverRegistry.isPublic(), false);
        assertEq(riverRegistry.payoutRecipient(), payout.addr);
        assertEq(riverRegistry.price(), 0);
    }

    function test_toggleIsPublic() public {
        vm.startPrank(trusted.addr);
        bool isPublicStatus = riverRegistry.isPublic();
        bool newStatus = riverRegistry.toggleIsPublic();
        assertEq(isPublicStatus, !newStatus);
    }

    function test_revertOnlyTrusted_toggleIsPublic() public {
        vm.startPrank(malicious.addr);
        vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
        riverRegistry.toggleIsPublic();
    }


    // only owner
    // pause
    // change price
    // change withdraw
    // payout recipient
    // increase + decrease allowance
    // withdraw

    // functionality to add 
    // public registrations on/off, settable by onlyTrusted
    // make these payable? to a recipient we can set? and we can upate the price?
    // allowlist registrations from beginning, settable by onlyTrusted

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                     MISC                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    function test_migrateAfterMigrationCutoff() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);        

        IRiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);  

        // reigster new id
        riverRegistry.trustedRegisterFor(randomishAccount(1000), recovery.addr, keyInits[0]);

        // process 199 migrations and run tests
        RiverRegistry.KeyInit[][] memory moreInits = generateKeyInits(cutoff);    
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount2 = randomishAccount(cutoff + i);
            address fromCustody = riverRegistry.custodyOf(i + 1);
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, moreInits[i]);            
            assertEq(riverRegistry.idOf(randomAccount2), i + 1);
            assertEq(riverRegistry.idOf(fromCustody), 0);
            assertEq(riverRegistry.custodyOf(i + 1), randomAccount2);
            assertEq(riverRegistry.recoveryOf(i + 1), recovery.addr);
            assertEq(riverRegistry.hasMigrated(i + 1), true);
        }        
    }   
}