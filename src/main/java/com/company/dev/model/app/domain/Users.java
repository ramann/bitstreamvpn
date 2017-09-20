package com.company.dev.model.app.domain;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.security.SecureRandom;

import com.company.dev.util.Util;
import org.apache.commons.codec.binary.Base64;

@Entity
@Table(name="users")
public class Users {
    private String username;
    private String password;
    private String salt;

    public Users() { }

    public Users(String username) {
        this.username = username;
    }

    public Users(String username, String password) {
        this.username = username;

        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[8];
        random.nextBytes(salt);

        this.password = Util.getHashedPassword(password,Base64.encodeBase64String(salt));
        this.salt = Base64.encodeBase64String(salt);
    }


    @Override
    public String toString() {
        return "Users{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", salt='" + salt + '\'' +
                '}';
    }

    @Id
    @Column(name = "username", nullable = false, length = 30)
    @Size(min=3)
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Basic
    @Column(name = "password", nullable = false, length = 64)
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Basic
    @Column(name = "salt", nullable = false, length = 16)
    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Users users = (Users) o;

        if (username != null ? !username.equals(users.username) : users.username != null) return false;
        if (password != null ? !password.equals(users.password) : users.password != null) return false;
        if (salt != null ? !salt.equals(users.salt) : users.salt != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (salt != null ? salt.hashCode() : 0);
        return result;
    }
}
