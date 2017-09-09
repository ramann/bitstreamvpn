package com.company.dev.model.app.repo;

import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface SubscriptionDao extends CrudRepository<Subscription, Long> {

    /**
     * Return the user having the passed email or null if no user is found.
     *
     * @param username the user name.
     */
    public List<Subscription> findByUsers(Users user);

    public Subscription findById(int id);

} // class UserDao