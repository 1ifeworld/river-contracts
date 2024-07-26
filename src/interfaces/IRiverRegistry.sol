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
    // exceeds max cutoff of keys per rid
    error Exceeds_Maximum();
    // invalid
    error Invalid_Key_State();
    //
    error Unauthorized();

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
    event Migrate(uint256 indexed id);    
    event ChangeRecoveryAddress(uint256 indexed id, address indexed recovery);

    /**
     * @dev Emit an event when an rid is recovered.
     *
     * @param from The custody address that previously owned the rid
     * @param to   The custody address that now owns the rid
     * @param id   The rid that was recovered
     */
    event Recover(address indexed from, address indexed to, uint256 indexed id);    

    event Add(
        uint256 indexed rid,
        uint32 indexed keyType,
        bytes indexed key,
        bytes keyBytes
    );
    event Remove(uint256 indexed rid, bytes indexed key, bytes keyBytes);   
}