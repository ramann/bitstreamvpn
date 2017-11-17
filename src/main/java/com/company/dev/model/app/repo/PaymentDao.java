package com.company.dev.model.app.repo;

import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.sql.Time;
import java.sql.Timestamp;
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
public interface PaymentDao extends CrudRepository<Payment, Long> {

    public Payment findByIdAndSubscription_UsersAndDateInitiatedIsNullAndInErrorIsFalse(int paymentId, Users users);

    public List<Payment> findBySubscriptionAndSubscription_UsersAndDateInitiatedIsNullAndDateCreatedIsGreaterThan(
            Subscription subscription, Users users, Timestamp timestamp);

    public List<Payment> findBySubscriptionAndSubscription_UsersAndDateInitiatedIsNotNullAndDateConfirm1IsNullAndInErrorIsFalseOrderByDateCreatedAsc(
            Subscription subscription, Users users);

    public List<Payment> findBySubscriptionAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(Subscription subscription);

    public List<Payment> findBySubscriptionAndSubscription_UsersAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(
            Subscription subscription, Users users);

    public Payment findByReceivingAddress(String address);

} // class UserDao
