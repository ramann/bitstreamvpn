package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.CertificateIdentity;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface CertificateIdentityDao extends CrudRepository<CertificateIdentity, Long> {


} // class UserDao
