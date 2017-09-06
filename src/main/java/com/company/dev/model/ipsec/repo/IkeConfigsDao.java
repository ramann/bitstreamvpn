package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.IkeConfigs;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface IkeConfigsDao extends CrudRepository<IkeConfigs, Long> {
    public IkeConfigs findById(int id);
} // class UserDao
