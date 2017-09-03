package com.company.dev.model.ipsec.repo;


import com.company.dev.model.ipsec.domain.Identities;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;


@Transactional
public interface IdentitiesDao extends CrudRepository<Identities, Long> {


    public Identities findById(int certificateId);
    public Identities findByData(byte[] data);

} // class UserDao
