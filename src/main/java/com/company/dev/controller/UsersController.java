package com.company.dev.controller;

import com.company.dev.model.Users;
import com.company.dev.model.UsersDao;
import com.company.dev.util.Util;
import com.github.cage.Cage;
import com.github.cage.YCage;
import org.apache.commons.codec.binary.Base64;
import org.apache.tomcat.jni.Time;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

@Controller
public class UsersController {

    /**
     * Generates captcha as image and returns the image path
     * stores the captcha code in the http session
     * and deletes older, unused captcha images.
     */
    @RequestMapping(value = "/generatecaptcha", method = RequestMethod.GET)
    public String generateCaptcha(Model model) { //ResponseEntity<CaptchaRequestData> generateCaptcha(HttpSession session) {
        //String captchaImageUploadDirectory = "/tmp/"; //= environment.getProperty("captcha_image_folder");
        String captchaWebAlias; // = environment.getProperty("captcha_web_alias");
        File tmpfile = null;
        try {
            tmpfile = File.createTempFile("temp", ".jpg");
        } catch (Exception e) {
            System.out.println(e);
        }

      //  String fileName = "temp" + "." + "jpg";
      //  String fullFilename = captchaImageUploadDirectory + fileName;

        //Generating the captcha code and setting max length to 4 symbols
        Cage currGcage = new YCage();
        String captchaToken = currGcage.getTokenGenerator().next();

        if (captchaToken.length() > 4) {
            captchaToken = captchaToken.substring(0, 4).toUpperCase();
        }

        //Setting the captcha token in http session
        //session.setAttribute("captchaToken", captchaToken);

        try {
            OutputStream os = new FileOutputStream(tmpfile, false);
            currGcage.draw(captchaToken, os);
            os.flush();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //CaptchaRequestData data = new CaptchaRequestData(captchaWebAlias + fileName);
        model.addAttribute("filename", tmpfile);
        return "generatecaptcha";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/")
    public String index(String filename, Model model) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filename)));
        } catch (Exception e) {
            System.out.println(e);
        }
        return "index";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/task")
    public String task(Model model) {
        return "task";
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
    public String greeting(@RequestParam(value="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }
    // ------------------------
    // PUBLIC METHODS
    // ------------------------

    @RequestMapping(method=RequestMethod.GET, value = "/resetpassword")
    public String resetPassword(Model model) {
        return "resetpassword";
    }

    @RequestMapping(method=RequestMethod.POST, value="/resetpassword")
    public String resetPassword(String password1, String password2, Model model) {
        return "fix me";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/viewproducts")
    public String viewProducts(Model model) {
        System.out.println("GET /viewproducts");
        return "viewproducts";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/login")
    public String login(Model model) {
        System.out.println("GET /login");
        return "login";
    }

    @RequestMapping(method=RequestMethod.POST, value = "/login")
    public String loginPost(String username, String password, Model model) {
        System.out.println("POST /login");
        try {
            System.out.println("username: "+username+", password: "+password);
            Users user = usersDao.findByUsername(username);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                System.out.println("invalid login");
                return "redirect:/login";
            }
        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            System.out.println("User not found");
            return "redirect:/login";
        }
        return "viewproducts";
    }

    /**
     * /create  --> Create a new user and save it in the database.
     *
     * @param username User's email
     * @param password User's name
     * @return A string describing if the user is succesfully created or not.
     */
    @RequestMapping("/create")
    @ResponseBody
    public String create(String username, String password, Model model) {
        Users user = null;
        try {
            user = new Users(username, password);
            usersDao.save(user);
        }
        catch (Exception ex) {
            return "Error creating the user: " + ex.toString();
        }
        return "User succesfully created! (id = " + user.getUsername() + ")";
    }

    /**
     * /delete  --> Delete the user having the passed id.
     *
     * @param username The id of the user to delete
     * @return A string describing if the user is succesfully deleted or not.
     */
    @RequestMapping("/delete")
    @ResponseBody
    public String delete(String username) {
        try {
            Users user = new Users(username);
            usersDao.delete(user);
        }
        catch (Exception ex) {
            return "Error deleting the user: " + ex.toString();
        }
        return "User succesfully deleted!";
    }

    /**
     * /get-by-email  --> Return the id for the user having the passed email.
     *
     * @param username The email to search in the database.
     * @return The user id or a message error if the user is not found.
     */
    @RequestMapping("/get-by-username")
    @ResponseBody
    public String getByEmail(String username) {
        String userId;
        try {
            Users user = usersDao.findByUsername(username);
            userId = String.valueOf(user.getUsername());
        }
        catch (Exception ex) {
            return "User not found";
        }
        return "The user id is: " + userId;
    }

    /**
     * /update  --> Update the email and the name for the user in the database
     * having the passed id.
     *
     * @param username The id for the user to update.
     * @param password The new email.
     * @param salt The new name.
     * @return A string describing if the user is succesfully updated or not.
     */
    @RequestMapping("/update")
    @ResponseBody
    public String updateUser(String username, String password, String salt) {
        try {
            Users user = usersDao.findByUsername(username);
            user.setPassword(password);
            user.setSalt(salt);
            usersDao.save(user);
        }
        catch (Exception ex) {
            return "Error updating the user: " + ex.toString();
        }
        return "User succesfully updated!";
    }

    // ------------------------
    // PRIVATE FIELDS
    // ------------------------

    @Autowired
    private UsersDao usersDao;

} // class UserController
