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

    function test_smartAccountPasskeySigner_registerFor() public {
        // start prank as trusted caller
        vm.startPrank(trusted.addr);
        // get deadline
        uint256 deadline = _deadline();
        // generate registerFor signature for passkeySigner on smart wallet
        bytes memory sig = _preparePasskeySigForSmartWallet(smartWallet, user, recovery.addr, deadline);
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
        (address undeployedSmartWallet, bytes memory sig) = _preparePasskey6492SigForSmartWallet(user, owners, recovery.addr, deadline);
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

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////               

    /* EOA STUFF */

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


    function _prepareEoa6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            idRegistryRegisterForHash,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        bytes32 smartWalletSafeHash = bytes32(address(generator).code);
        // this creates the signature of the owner of the smart wallet
        bytes memory eoaSigForOwner = _sign(_initialSigner.key, smartWalletSafeHash);
        // this creates the signature wrapper that is used to pass signatures inside of smart wallet runtime
        bytes memory encodedSignatureWrapper =
            abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner}));
        // this creates the account init data that will be used to simulate deploy of smart account
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );        
        // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), sigFor6492);
    }

    /* PASSKEY STUFF */

    function _preparePasskeySigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
        );        
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 2,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );
        return sig;                
    }        


    function _preparePasskey6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            idRegistryRegisterForHash,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        bytes32 smartWalletSafeHash = bytes32(address(generator).code);
        // formats webauthn
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
        // creates + cleans p256 sig
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));        
        // creates encoded signature wrapper
        bytes memory encodedSignatureWrapper = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 2,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );        
        // this creates the account init data that will be used to simulate deploy of smart account
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );        
        // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), sigFor6492);
    }
}
