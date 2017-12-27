package com.company.dev.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.file.Files;
import java.nio.file.Paths;

//@Configuration
@EnableWebSecurity
public class WebSecurityConfig /*extends WebSecurityConfigurerAdapter*/ {



    //@Override
    @Configuration
    public static class HtmlWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/", "/create", "/greeting", "/css/**", "/fonts/**", "/images/**",
                    "/js/**", "/header", "/footer", "/layout", "/task", "/generatecaptcha", "/createaccount",
                            "/enterpayment", "/accountcreated", "/instructions", "/signin", "/howitworks", "/about",
                            "/ourcert", "/faq")
                    .permitAll() //.anyRequest().permitAll(); //.and().csrf().disable();
                    .anyRequest()
                    .authenticated()
                    .and().formLogin().loginPage("/login").permitAll().and().logout().permitAll();
        }
    }

    @Configuration
    @Order(1)
    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/updatePayment").csrf().disable()
                    .httpBasic()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/updatePayment")
                    .authenticated()
                    ;
        }
    }

    @Configuration
    @Order(2)
    public static class Api2WebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/updateConfirmations").csrf().disable()
                    .httpBasic()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/updateConfirmations")
                    .authenticated()
            ;
        }
    }

    @Autowired
    private CustomAuthenticationProvider authProvider;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider);
    }
}
