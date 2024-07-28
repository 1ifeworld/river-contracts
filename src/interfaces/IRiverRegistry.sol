// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

interface IRiverRegistry {

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    ERRORS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */     

    /// @dev Revert when trying to call migrate after migrate cutoff reached
    error Past_Migration_Cutoff();
    /// @dev Revert when trying to call register before migrate cutoff reached
    error Before_Migration_Cutoff();
    /// @dev Revert when trying to migrate an rid that already has
    error Already_Migrated();
    /// @dev Revert when the caller must have an rid but does not have one
    error Has_No_Id();
    /// @dev Revert when the recipeint already has an rid
    error Has_Id();
    /// @dev Revert if exceeds max number of keys per rid
    error Exceeds_Maximum();
    /// @dev Revert if trying to adjust key state from an invalid key state
    error Invalid_Key_State();
    /// @dev Revert when the caller does not have the authority to perform the action.
    error Unauthorized();

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    TYPES                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */    

    /**
     *  @notice State enumeration for a key in the registry. During migration, an admin can change
     *          the state of any rids key from NULL to ADDED or ADDED to NULL. After migration, an
     *          rid can change the state of a key from NULL to ADDED or ADDED to REMOVED only.
     *
     *          - NULL: The key is not in the registry.
     *          - ADDED: The key has been added to the registry.
     *          - REMOVED: The key was added to the registry but is now removed.
     */
    enum KeyState {
        NULL,
        ADDED,
        REMOVED
    }

    /**
     *  @notice Data about a key.
     *
     *  @param state   The current state of the key.
     *  @param keyType Numeric ID representing the manner in which the key should be used.
     */
    struct KeyData {
        KeyState state;
        uint32 keyType;
    }

    /**
     *  @notice Init params for adding keys
     *
     *  @param keyType Numeric ID representing the manner in which the key should be used.
     *  @param key     Full bytes value for key being added.    
     */
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
    
    /**
     * @dev Emit an event when a new River ID is issued.
     *
     * @param to       The custody address that owns the rid.
     * @param id       The rid that was issued.
     * @param recovery The address that can initiate a recovery request for the rid.
     */    
    event Issue(address indexed to, uint256 id, address recovery);    

    /**
     * @dev Emit an event when a River ID migrated.
     *
     * @param id       The rid that was migrated.
     */  
    event Migrate(uint256 indexed id);     

    /**
     * @dev Emit an event when an rid is transferred to a new custody address.
     *
     * @param from The custody address that previously owned the rid.
     * @param to   The custody address that now owns the rid.
     * @param id   The rid that was transferred.
     */   
    event Transfer(address indexed from, address indexed to, uint256 indexed id);   

    /**
     * @dev Emit an event when a River ID's recovery address changes. It is possible for this
     *      event to emit multiple times in a row with the same recovery address.
     *
     * @param id       The rid whose recovery address was changed.
     * @param recovery The new recovery address.
     */
    event ChangeRecoveryAddress(uint256 indexed id, address indexed recovery);

    /**
     * @dev Emit an event when an rid is recovered.
     *
     * @param from The custody address that previously owned the rid
     * @param to   The custody address that now owns the rid
     * @param id   The rid that was recovered
     */
    event Recover(address indexed from, address indexed to, uint256 indexed id);    

    /**
     * @dev Emit an event when an rid is recovered.
     *
     * @param from The custody address that previously owned the rid
     * @param to   The custody address that now owns the rid
     * @param id   The rid that was recovered
     */

    /**
     * @dev Emit an event when an rid adds a new key.
     *
     * @param rid          The rid associated with the key.
     * @param keyType      The type of the key.
     * @param key          The key being registered. (indexed as hash)
     * @param keyBytes     The bytes of the key being registered.     
     */     
    event Add(
        uint256 indexed rid,
        uint32 indexed keyType,
        bytes indexed key,
        bytes keyBytes
    );

    /**
     * @dev Emit an event when an rid removes an added key.
     *
     * @param rid       The rid associated with the key.
     * @param key       The key being registered. (indexed as hash)
     * @param keyBytes  The bytes of the key being removed.   
     */        
    event Remove(uint256 indexed rid, bytes indexed key, bytes keyBytes);   
}