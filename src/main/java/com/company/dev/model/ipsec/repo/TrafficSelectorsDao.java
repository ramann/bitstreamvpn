package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.TrafficSelectors;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;

@Transactional
public interface TrafficSelectorsDao  extends CrudRepository<TrafficSelectors, Long> {
    public TrafficSelectors findById(int id);
}
