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

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////    

    function test_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        for (uint256 i; i < migrationCutoff; ++i) {
            address randomAccount = randomAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }

        assertEq(riverRegistry.idCount(), migrationCutoff);
    }

    function test_revert_untrusted_prepMigrate() public {
        // start prank as untrusted caller
        vm.startPrank(malicious.addr);

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();

        for (uint256 i; i < migrationCutoff; ++i) {
            address randomAccount = randomAccount(i);
            vm.expectRevert(abi.encodeWithSignature("Only_Trusted()"));
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
            break;
        }
    }       

    function test_revert_dupCustody_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();
        address duplicate;

        for (uint256 i; i < migrationCutoff; ++i) {
            address randomAccount = randomAccount(i);
            if (i == 0) {
                duplicate = randomAccount;
            }
            if (i == 1) {
                vm.expectRevert(abi.encodeWithSignature("Has_Id()"));
                riverRegistry.trustedPrepMigration(duplicate, recovery.addr);
                break;
            }        
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }
    }       

    function test_revert_pastCutoff_prepMigrate() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);

        uint256 migrationCutoff = riverRegistry.RID_MIGRATION_CUTOFF();
        uint256 pastCutoff = migrationCutoff + 1;

        for (uint256 i; i < pastCutoff; ++i) {
            address randomAccount = randomAccount(i);
            if (i == migrationCutoff) {
                vm.expectRevert(abi.encodeWithSignature("Past_Migration_Cutoff()"));
            }            
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }
    }     
}