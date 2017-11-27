package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Connections;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
@Repository
public interface ConnectionsDao extends CrudRepository<Connections, Long> {

    public List<Connections> findByPeerIdAndDisconnected(String peerId, boolean disconnected);
}
