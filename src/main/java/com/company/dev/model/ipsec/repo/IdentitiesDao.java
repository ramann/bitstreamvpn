package com.company.dev.model.ipsec.repo;


import com.company.dev.model.ipsec.domain.Identities;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;


@Transactional
@Repository
public interface IdentitiesDao extends CrudRepository<Identities, Long> {


    public Identities findById(int certificateId);
    public Identities findByData(byte[] data);

    @Query("from Identities i where cast(i.type as binary) = cast(?1 as binary) and cast(i.data as binary) = cast(?2 as binary)")
    public Identities findByTypeAndData(byte type, byte[] data);

} // class UserDao
