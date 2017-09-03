package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.ChildConfigs;
import com.company.dev.model.ipsec.domain.Pools;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface ChildConfigsDao extends CrudRepository<ChildConfigs, Long> {

} // class UserDao
