package com.company.dev.model;

import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;


/**
 * A DAO for the entity User is simply created by extending the CrudRepository
 * interface provided by spring. The following methods are some of the ones
 * available from such interface: save, delete, deleteAll, findOne and findAll.
 * The magic is that such methods must not be implemented, and moreover it is
 * possible create new query methods working only by defining their signature!
 *
 * @author netgloo
 */
@Transactional
public interface PurchaseDao extends CrudRepository<Purchase, Long> {

    /**
     * Return the user having the passed email or null if no user is found.
     *
     * @param username the user name.
     */
    public List<Purchase> findByUsers(Users users);

    public Purchase findById(int purchaseId);

} // class UserDao
