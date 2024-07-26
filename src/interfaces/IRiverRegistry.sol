// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @dev RiverRegistry Interface
 */
interface IRiverRegistry {

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    ERRORS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */     

    error Past_Migration_Cutoff();
    error Before_Migration_Cutoff();
    error Already_Migrated();
    error Has_No_Id();
    error Has_Id();
    //
    error ExceedsMaximum();
    error ValidatorNotFound(uint32 keyType, uint8 metadataType);
    error InvalidState();

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    TYPES                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */    

    enum KeyState {
        NULL,
        ADDED,
        REMOVED
    }

    struct KeyData {
        KeyState state;
        uint32 keyType;
    }

    struct KeyInit {
        uint32 keyType;
        bytes key;
    }    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    EVENTS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    event Issue(address indexed to, uint256 id, address recovery);    
    event Transfer(address indexed from, address indexed to, uint256 indexed id);
    event Add(
        uint256 indexed rid,
        uint32 indexed keyType,
        bytes indexed key,
        bytes keyBytes
    );
    event Migrate(uint256 indexed id);    
    event ChangeRecoveryAddress(uint256 indexed id, address indexed recovery);
}