package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Certificates;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface CertificatesDao extends CrudRepository<Certificates, Long> {


    public Certificates findById(int certificateId);
    public Certificates findByData(byte[] data);

} // class UserDao
