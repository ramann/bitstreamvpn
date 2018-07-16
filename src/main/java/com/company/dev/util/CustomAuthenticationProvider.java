package com.company.dev.util;


import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.UsersDao;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();
        ArrayList authorities = new ArrayList<>();

        try {
            logger.debug("trying to authenticate: "+name);
            Users user = usersDao.findByUsername(name);
            byte[] hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if (!Arrays.equals(hashedPassword,user.getPassword())) {
                logger.info("invalid login for "+name);
                return null;
            }

            if(user.isAdmin()) {
                authorities.add(new SimpleGrantedAuthority("ADMIN"));
            }

        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, slt);

            logger.info("User "+name+" not found");
            return null;
        }

        return new UsernamePasswordAuthenticationToken(name, password, authorities);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    @Autowired
    private UsersDao usersDao;
}