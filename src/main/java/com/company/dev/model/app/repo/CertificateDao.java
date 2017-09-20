package com.company.dev.model.app.repo;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
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
public interface CertificateDao extends CrudRepository<Certificate, Long> {

    public List<Certificate> findBySubscriptionAndSubscription_UsersOrderByDateCreated(Subscription subscription, Users users);
    public Certificate findBySerialAndSubscription_Users(long serial, Users users);

} // class UserDao
