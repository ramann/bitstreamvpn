package com.company.dev.model.ipsec.repo;

import com.company.dev.model.ipsec.domain.ChildConfigTrafficSelector;
import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
public interface ChildConfigTrafficSelectorDao extends CrudRepository<ChildConfigTrafficSelector, Long> {
    public List<ChildConfigTrafficSelector> findByChildCfg(int childCfg);
}

