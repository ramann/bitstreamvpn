package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Addresses;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface AddressesDao extends CrudRepository<Addresses, Long> {

} // class UserDao
