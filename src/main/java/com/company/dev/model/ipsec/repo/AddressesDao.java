package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Addresses;
import com.company.dev.model.ipsec.domain.Identities;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface AddressesDao extends CrudRepository<Addresses, Long> {

    public List<Addresses> findByIdentityIs(int identity);
    public List<Addresses> findAll();
}
