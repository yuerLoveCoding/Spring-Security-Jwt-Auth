package github.javaguide.springsecurityjwtguide.security.entity;

import lombok.Data;


/**
 * @author shuang.kou
 */
@Data
public class LoginUser {

    private String username;
    private String userpass;
    private Boolean rememberMe;

}
