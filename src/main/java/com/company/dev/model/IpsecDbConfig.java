package com.company.dev.model;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        entityManagerFactoryRef = "ipsecEntityManagerFactory",
        transactionManagerRef = "ipsecTransactionManager",
        basePackages = { "com.company.dev.model.ipsec.repo" }
)
public class IpsecDbConfig {

    @Bean(name = "ipsecDataSource")
    @ConfigurationProperties(prefix = "ipsec.datasource")
    public DataSource dataSource() {
        return DataSourceBuilder.create().build();
    }

    @Bean(name = "ipsecEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean
    ipsecEntityManagerFactory(
            EntityManagerFactoryBuilder builder,
            @Qualifier("ipsecDataSource") DataSource dataSource
    ) {
        return
                builder
                        .dataSource(dataSource)
                        .packages("com.company.dev.model.ipsec.domain")
                        .persistenceUnit("ipsec")
                        .build();
    }

    @Bean(name = "ipsecTransactionManager")
    public PlatformTransactionManager ipsecTransactionManager(
            @Qualifier("ipsecEntityManagerFactory") EntityManagerFactory
                    ipsecEntityManagerFactory
    ) {
        return new JpaTransactionManager(ipsecEntityManagerFactory);
    }
}