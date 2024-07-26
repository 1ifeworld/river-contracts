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
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);            
            assertEq(riverRegistry.idOf(randomAccount2), i + 1);
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
            riverRegistry.trustedMigrateFor(i + 1, randomAccount2, recovery.addr, keyInits[i]);
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

    // other cases
    // - NOTE: handle this in the register tests: should work for rids 1-200 even once other ids are being registered via normal register post 200      

    //////////////////////////////////////////////////
    // REGISTER
    //////////////////////////////////////////////////       

    // invariants   
    //    

    //////////////////////////////////////////////////
    // REGISTER FOR
    //////////////////////////////////////////////////        

    // invariants   
    //

    //////////////////////////////////////////////////
    // TRUSTED REGISTER FOR
    ////////////////////////////////////////////////// 

    // invariants
    // - only trusted - X
    // - only for rids 201+ - x 
    // - only if recipient has no id - x                 
    // - fails if paused    
    
    function test_trustedRegisterFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // process prep migration
        _prepMigrateForAccounts(cutoff);

        address randomCustody = randomishAccount(uint256(keccak256(bytes("trustedRegisterFor"))));   
        RiverRegistry.KeyInit[][] memory keyInits = generateKeyInits(1);   

        riverRegistry.trustedRegisterFor();
    }                

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 ID TRANSFERS                   *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    //////////////////////////////////////////////////
    // TRANSFER
    //////////////////////////////////////////////////       

    //////////////////////////////////////////////////
    // TRANSFER FOR
    //////////////////////////////////////////////////            

    //////////////////////////////////////////////////
    // TRANSFER AND CHANGE RECOVERY ????
    //////////////////////////////////////////////////          

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

    //////////////////////////////////////////////////
    // RECOVER FOR
    //////////////////////////////////////////////////          

    //////////////////////////////////////////////////
    // CHANGE RECOVERY
    //////////////////////////////////////////////////              

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                  KEY ADD                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    //////////////////////////////////////////////////
    // ADD
    //////////////////////////////////////////////////         

    //////////////////////////////////////////////////
    // ADD FOR
    //////////////////////////////////////////////////             

    //////////////////////////////////////////////////
    // ??? TRUSTED ADD FOR 
    //////////////////////////////////////////////////                 

    // is this bad vibes 0_0

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *               KEY REMOVAL                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    //////////////////////////////////////////////////
    // REMOVE
    //////////////////////////////////////////////////         

    //////////////////////////////////////////////////
    // REMOVE FOR
    //////////////////////////////////////////////////   

    //////////////////////////////////////////////////
    // ??? TRUSTED REMOVE FOR 
    //////////////////////////////////////////////////                      

    //////////////////////////////////////////////////
    // KEY MGMT - Add, Remove, Reset
    //////////////////////////////////////////////////    

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

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *          PAUSING + ALLOWLIST + PUBLIC          *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    // functionality to add 
    // public registrations on/off, settable by onlyTrusted
    // make these payable? to a recipient we can set? and we can upate the price?
    // allowlist registrations from beginning, settable by onlyTrusted
}