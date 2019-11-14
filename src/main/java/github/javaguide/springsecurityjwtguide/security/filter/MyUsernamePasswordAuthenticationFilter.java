//package github.javaguide.springsecurityjwtguide.security.filter;
//
//import io.jsonwebtoken.lang.Assert;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.AuthenticationServiceException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//
///**
// * 类功能描述：</br>
// *
// * @author yuyahao
// * @version 1.0 </p> 修改时间：13/11/2019</br> 修改备注：</br>
// */
//public class MyUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
//    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
//    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "userpass";
//    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
//    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
//    private boolean postOnly = true;
////    private String privateKey = "xxxxxxxxxxxxxxxxxxx";
//
//    public MyUsernamePasswordAuthenticationFilter() {
//        super(new AntPathRequestMatcher("/oauth/token", "POST"));
//    }
//
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//        if (postOnly && !request.getMethod().equals("POST")) {
//            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
//        }
//        String username = obtainUsername(request);
//        String password = obtainPassword(request);
//        /*try {
//            password = RSAUtil.decrypt(password, privateKey);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//*/
//        if (username == null) {
//            username = "";
//        }
//
//        if (password == null) {
//            password = "";
//        }
//
//        username = username.trim();
//
////        JWTAuthenticationFilter  jwtAuthenticationFilter = new JWTAuthenticationFilter( );
//
//        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
//
//        // Allow subclasses to set the "details" property
//        setDetails(request, authRequest);
//
//        return super.getAuthenticationManager().authenticate(authRequest);
//    }
//
//    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
//        super.setAuthenticationManager(authenticationManager);
//    }
//
//    protected String obtainPassword(HttpServletRequest request) {
//        return request.getParameter(passwordParameter).replaceAll(" ", "+");
//    }
//
//    protected String obtainUsername(HttpServletRequest request) {
//        return request.getParameter(usernameParameter);
//    }
//
//    protected void setDetails(HttpServletRequest request,
//                              UsernamePasswordAuthenticationToken authRequest) {
//        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
//    }
//
//    public void setUsernameParameter(String usernameParameter) {
//        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
//        this.usernameParameter = usernameParameter;
//    }
//
//    public void setPasswordParameter(String passwordParameter) {
//        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
//        this.passwordParameter = passwordParameter;
//    }
//
//    public void setPostOnly(boolean postOnly) {
//        this.postOnly = postOnly;
//    }
//
//    public final String getUsernameParameter() {
//        return usernameParameter;
//    }
//
//    public final String getPasswordParameter() {
//        return passwordParameter;
//    }
//
//}