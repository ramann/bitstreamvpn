package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.Certificates;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface CertificatesDao extends CrudRepository<Certificates, Long> {


    public Certificates findById(int certificateId);
    public Certificates findByData(byte[] data);
    public List<Certificates> findAll();

} // class UserDao
