package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.CertificateAuthorities;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface CertificateAuthoritiesDao extends CrudRepository<CertificateAuthorities, Long> {


} // class UserDao
