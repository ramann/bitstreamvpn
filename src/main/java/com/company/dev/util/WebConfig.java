package com.company.dev.util;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebConfig extends WebMvcConfigurerAdapter {

    @Bean
    public MethodValidationPostProcessor methodValidationPostProcessor() {
        return new MethodValidationPostProcessor();
    }

    // https://spring.io/blog/2013/05/11/content-negotiation-using-spring-mvc
    // We ignore the Accept header, because on bad requests without, the response will be something like
    // {"timestamp":1505583404820,"status":400,"error":"Bad Request","exception":"java.lang.IllegalStateException","message":"Bad Request","path":"/certs"}
    // and we don't need to tell people what the exception is
    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer
                .ignoreAcceptHeader(true)
                .defaultContentType(MediaType.TEXT_HTML);
    }

}
