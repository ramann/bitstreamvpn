package com.company.dev.util;


import com.company.dev.model.Users;
import com.company.dev.model.UsersDao;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider
        implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        System.out.println("entered authenticate");

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        System.out.println("name: "+name);
        System.out.println("password: "+password);
        //if (shouldAuthenticateAgainstThirdPartySystem()) {

        try {
            System.out.println("username: "+name+", password: "+password);
            Users user = usersDao.findByUsername(name);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                System.out.println("invalid login");
                return null;
            }
        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            System.out.println("User not found");
            return null;
        }
            // use the credentials
            // and authenticate against the third-party system
            return new UsernamePasswordAuthenticationToken(
                    name, password, new ArrayList<>());
        /*} else {
            return null;
        }*/
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                UsernamePasswordAuthenticationToken.class);
    }

    @Autowired
    private UsersDao usersDao;
}