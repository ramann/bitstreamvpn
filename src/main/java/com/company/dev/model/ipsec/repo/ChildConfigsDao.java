package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.ChildConfigs;
import com.company.dev.model.ipsec.domain.Pools;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface ChildConfigsDao extends CrudRepository<ChildConfigs, Long> {

    ChildConfigs findById(int id);
    List<ChildConfigs> findAll();
} // class UserDao
