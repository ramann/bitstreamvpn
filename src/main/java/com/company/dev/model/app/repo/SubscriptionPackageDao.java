package com.company.dev.model.app.repo;

import com.company.dev.model.app.domain.SubscriptionPackage;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface SubscriptionPackageDao extends CrudRepository<SubscriptionPackage, Long> {

    public SubscriptionPackage findById(int Id);

    public List<SubscriptionPackage> findAll();
}
