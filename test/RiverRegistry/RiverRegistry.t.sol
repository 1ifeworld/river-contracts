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

    // other cases
    // - NOTE: handle this in the register tests: should work for rids 1-200 even once other ids are being registered via normal register post 200    

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

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        for (uint256 i; i < migrationCutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        assertEq(riverRegistry.idCount(), migrationCutoff);
    }

    function test_revert_untrusted_prepMigrate() public {
        // start prank as untrusted caller
        vm.startPrank(malicious.addr);

        address randomAccount = randomishAccount(1);
        vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
        riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        assertEq(riverRegistry.idCount(), 0);
    }       

    function test_revert_dupCustody_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        address randomAccount = randomishAccount(1);
        riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);

        assertEq(riverRegistry.custodyOf(1), randomAccount);

        vm.expectRevert(abi.encodeWithSignature("Has_Id()"));
        riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        assertEq(riverRegistry.idCount(), 1);
    }       

    function test_revert_pastCutoff_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        for (uint256 i; i < migrationCutoff; ++i) {
            address randomAccount = randomishAccount(i);     
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        address anotherRandomAccount = randomishAccount(migrationCutoff + 1);
        vm.expectRevert(abi.encodeWithSignature("Past_Migration_Cutoff()"));
        riverRegistry.trustedPrepMigration(anotherRandomAccount, recovery.addr);
        assertEq(riverRegistry.idCount(), migrationCutoff);
    }     

    //////////////////////////////////////////////////
    // TRUSTED MIGRATE FOR
    //////////////////////////////////////////////////     

    function test_trustedMigrateFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        // cache migration cutoff
        uint256 cutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        // prep migration
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        // process 200 migrations and run tests
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff);    
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

        // prep migration
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        vm.stopPrank();
        vm.startPrank(malicious.addr);

        // process 200 migrations and run tests
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff);    
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

        // prep migration
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        // process 200 migrations and run tests
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff + 1);    
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

        // prep migration
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        // process 200 migrations and run tests
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff);    
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
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff);    
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

        // prep migration
        for (uint256 i; i < cutoff; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        // process 200 migrations and run tests
        RiverRegistry.KeyRegistration[][] memory keyInits = generateKeyInits(cutoff);    
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
}