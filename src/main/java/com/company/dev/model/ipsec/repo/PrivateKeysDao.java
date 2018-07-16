package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.PrivateKeys;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface PrivateKeysDao extends CrudRepository<PrivateKeys, Long> {

    public List<PrivateKeys> findAll();
} // class UserDao
