// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {KeyRegistryTest} from "../KeyRegistry/KeyRegistryTest.t.sol";
import {Bundler} from "../../src/Bundler.sol";

abstract contract BundlerTestSuite is KeyRegistryTest {
    Bundler bundler;

    function setUp() public virtual override {
        super.setUp();

        // Set up the BundleRegistry
        bundler = new Bundler(
            address(idRegistry),
            address(keyRegistry)
        );
    }

    // Assert that a given fname was correctly registered with id 1 and recovery
    function _assertSuccessfulRegistration(address account, address recovery) internal {
        assertEq(idRegistry.idOf(account), 1);
        assertEq(idRegistry.recoveryOf(1), recovery);
    }

    // Assert that a given fname was not registered and the contracts have no registrations
    function _assertUnsuccessfulRegistration(address account) internal {
        assertEq(idRegistry.idOf(account), 0);
        assertEq(idRegistry.recoveryOf(1), address(0));
    }
}