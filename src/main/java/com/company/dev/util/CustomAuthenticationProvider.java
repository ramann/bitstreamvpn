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
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        try {
            logger.debug("trying to authenticate: "+name);
            Users user = usersDao.findByUsername(name);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                logger.info("invalid login for "+name);
                return null;
            }
        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            logger.info("User "+name+" not found");
            return null;
        }

        return new UsernamePasswordAuthenticationToken(name, password, new ArrayList<>());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    @Autowired
    private UsersDao usersDao;
}