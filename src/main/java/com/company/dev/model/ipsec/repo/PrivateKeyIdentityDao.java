package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.PrivateKeyIdentity;
import com.company.dev.model.ipsec.domain.TrafficSelectors;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface PrivateKeyIdentityDao extends CrudRepository<PrivateKeyIdentity, Long> {

    public List<PrivateKeyIdentity> findAll();
}
