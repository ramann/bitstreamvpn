package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.PeerConfigChildConfig;
import com.company.dev.model.ipsec.domain.PeerConfigs;
import org.bitcoinj.core.Peer;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface PeerConfigChildConfigDao extends CrudRepository<PeerConfigChildConfig, Long> {

    public PeerConfigChildConfig findByPeerCfg(int peerCfg);
    public List<PeerConfigChildConfig> findAll();
} // class UserDao
