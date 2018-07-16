package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.PeerConfigs;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface PeerConfigsDao extends CrudRepository<PeerConfigs, Long> {

    public PeerConfigs findByRemoteId(String remoteId);
    public List<PeerConfigs> findAll();
} // class UserDao
