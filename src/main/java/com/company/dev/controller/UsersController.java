package com.company.dev.controller;

import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.util.Util;
import com.github.cage.Cage;
import com.github.cage.YCage;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Set;

import static java.lang.System.out;

//import org.bouncycastle.asn1.*;

@Controller
@Validated
public class UsersController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method=RequestMethod.GET, value="/createaccount")
    public String createAccount(Users users, Model model)
    {
        model.addAttribute("page", "createaccount");
        return "createaccount";
    }

    @ExceptionHandler(value = { ConstraintViolationException.class })
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public String validateAccountSetup(ConstraintViolationException e, Model model, HttpServletRequest request, HttpSession session) {
        Set<ConstraintViolation<?>> violations = e.getConstraintViolations();
        StringBuilder strBuilder = new StringBuilder();
        for (ConstraintViolation<?> violation : violations ) {
            strBuilder.append(violation.getMessage() + "\n");
            if(violation.getMessage().contains("Username")) {
                out.println("username_error");
                model.addAttribute("username_error", violation.getMessage());
                model.addAttribute("username", "");
            }
            if(violation.getMessage().contains("Password confirmation")) {
                model.addAttribute("password_confirm_error", violation.getMessage());
            }
            if(violation.getMessage().contains("Password must")) {
                model.addAttribute("password_error", violation.getMessage());
            }
            if(violation.getMessage().contains("CAPTCHA")) {
                model.addAttribute("captcha_error", violation.getMessage());
            }
        }

        if (!model.containsAttribute("password_error") &&
                !model.containsAttribute("password_confirm_error") &&
                !request.getParameter("password").equals(request.getParameter("confirmPassword"))) {
            model.addAttribute("password_confirm_error", "Password and password confirmation are not equal");
        }
        if (!model.containsAttribute("captcha_error") &&
                !request.getParameter("captcha").equals(session.getAttribute("captchaToken"))) {
            model.addAttribute("captcha_error", "CAPTCHA value didn't match.");
        }

        if(!model.containsAttribute("username_error")) {
            model.addAttribute("username", request.getParameter("username"));
        }

        session.setAttribute("captchaToken", null);

        return "createaccount";
    }

    @RequestMapping(method=RequestMethod.POST, value="/createaccount")
    public String accountSetup(@Pattern(regexp="^[a-zA-Z0-9]{3,10}$", message="Username must be 3 to 10 alphanumeric characters")
                                                String username,
                                    /*@Pattern(regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\p{Punct}).{4,10}$",
                                            message="Password must be between 4 and 10 characters long and contain a lowercase, uppercase, numeral, and punctuation character.")*/
                               @Size(min=4, max=10, message="Password must be 4 to 10 characters")
                                            String password,
                                    /*@Pattern(regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\p{Punct}).{4,10}$",
                                            message="Password must be between 4 and 10 characters long and contain a lowercase, uppercase, numeral, and punctuation character.")*/
                                    /* @Pattern(regexp="^{4,10}$", message="Password confirmation didn't match") */
                                                String confirmPassword,
                                    /*@Pattern(regexp="^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", message="You must enter a Bitcoin address")
                                                String btc,*/
                                    /*@Size(min=7, max=7, message="CAPTCHA value is wrong.")*/ String captcha,
                                    Model model, HttpSession session) //String confirm_password, String btc, Model model,HttpSession session,
    {
        // We do this validation here because the annotations above won't catch these.
        boolean errors = false;
        if( !captcha.equals(session.getAttribute("captchaToken"))) {
            model.addAttribute("captcha_error", "It looks like you've entered the wrong CAPTCHA value, here's a different one to try.");
            errors = true;
        }
        if( !password.equals(confirmPassword)) {
            model.addAttribute("password_confirm_error", "Password and password confirmation are not equal");
            errors = true;
        }
        if (usersDao.findByUsername(username) != null) {
            model.addAttribute("username_exists_error", "Username has already been taken");
            errors = true;
        } else {
            model.addAttribute("username", username);
        }
        if(errors) {
            return "createaccount";
        }

        Users user = null;
        try {
            user = new Users(username, password);
            usersDao.save(user);
            session.setAttribute("username", username);
        }
        catch (Exception ex) {
            logger.error("Error creating the user: " + ex.toString());
        }
        logger.info("User succesfully created! (id = " + user.getUsername() + ")");

        return "redirect:/accountcreated";
    }

    @RequestMapping(method=RequestMethod.GET, value="accountcreated")
    public String accountCreated(Model model, HttpSession session) {
        logger.info("/accountcreated");
        model.addAttribute("username", session.getAttribute("username"));
        session.setAttribute("username", null);
        return "accountcreated";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/")
    public String index(String filename, Model model) {
        String msg = "-------------------------- TESTING LOG ENTRY --------------------------";
        logger.error(msg);
        logger.warn(msg);
        logger.info(msg);
        logger.trace(msg);
        logger.debug(msg);
        return "index";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/layout")
    public String layout(Model model) {
        return "layout";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/header")
    public String header(Model model) {
        return "header";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/footer")
    public String footer(Model model) {
        return "footer";
    }

    @RequestMapping("/greeting")
    public String greeting(@RequestParam(value="name", required=false, defaultValue="World") String name, Model model, HttpSession session) {
        model.addAttribute("name", name);
        model.addAttribute("captchaToken", session.getAttribute("captchaToken"));
        return "greeting";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/login")
    public String login(Model model) {
        logger.info("GET /login");
        return "login";
    }

    @RequestMapping(method=RequestMethod.POST, value = "/login")
    public String loginPost(String username, String password, HttpSession session, Model model) {
        logger.info("POST /login");
       /* try {*/
        if (usersDao.findByUsername(username) != null) {
            logger.debug("username: " + username + ", password: " + password);
            Users user = usersDao.findByUsername(username);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if (!hashedPassword.equals(user.getPassword())) {
                logger.warn("invalid login");
                return "redirect:/login";
            }
            session.setAttribute("username", user.getUsername());
            logger.info("/login username---->" + username);
/*
        } catch (Exception ex) {
*/
        } else {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            logger.warn("User not found");
            return "redirect:/login";
        }
        return "viewproducts";
    }



    /**
     * Generates captcha as image and returns the image path
     * stores the captcha code in the http session
     * and deletes older, unused captcha images.
     */
    @RequestMapping(value = "/generatecaptcha", method = RequestMethod.GET)
    public void generateCaptcha(Model model, HttpServletResponse response, HttpSession session) { //ResponseEntity<CaptchaRequestData> generateCaptcha(HttpSession session) {
        Cage currGcage = new YCage();
        String captchaToken = currGcage.getTokenGenerator().next();
        logger.debug("captchaToken: "+captchaToken);

        //Setting the captcha token in http session
        session.setAttribute("captchaToken", captchaToken);

        response.setContentType("image/jpeg");
        try {
            OutputStream os = response.getOutputStream();
            currGcage.draw(captchaToken, os);

            response.flushBuffer();
        } catch (IOException ex) {
            logger.error("Error writing captcha to output stream.");
            throw new RuntimeException("IOError writing file to output stream");
        }
    }

    // ------------------------
    // PRIVATE FIELDS
    // ------------------------

    @Autowired
    private UsersDao usersDao;

} // class UserController
