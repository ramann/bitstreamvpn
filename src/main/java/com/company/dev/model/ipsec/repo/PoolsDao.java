package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Pools;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface PoolsDao extends CrudRepository<Pools, Long> {

    public List<Pools> findAll();
} // class UserDao
