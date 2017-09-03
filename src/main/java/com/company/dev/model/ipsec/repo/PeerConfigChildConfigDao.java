package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.PeerConfigChildConfig;
import com.company.dev.model.ipsec.domain.PeerConfigs;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface PeerConfigChildConfigDao extends CrudRepository<PeerConfigChildConfig, Long> {

} // class UserDao
