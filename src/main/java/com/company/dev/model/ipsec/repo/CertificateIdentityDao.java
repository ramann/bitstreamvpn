package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.CertificateIdentity;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface CertificateIdentityDao extends CrudRepository<CertificateIdentity, Long> {

    public CertificateIdentity findByCertificateAndIdentity(int certificate, int identity);
    public CertificateIdentity findByCertificate(int certificate);
} // class UserDao
