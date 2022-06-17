package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity//웹보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //부모코드
//        this.logger.debug("Using default configure(HttpSecurity). "
//                + "If subclassed this will potentially override subclass configure(HttpSecurity).");
//        http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
//        http.formLogin();
//        http.httpBasic();
        
        
        //인가
        http
            .authorizeRequests()               //http요청에 대해 아래의 보안검사를 하겠다!!!
                .anyRequest().authenticated()  //모든요청에 대해 인증이 필요하다.
        ;

        //인증
        http
                //[로그인화면]
                .formLogin().permitAll()  //loginPage("/loginPage")에 대한 접근권한을 모두에게 주겠다.
              //.loginPage("/loginPage")  //로그인페이지 커스텀지정

                //[로그인 url]
                .loginProcessingUrl("/login_proc")

                //[인증 요청파라미터의 이름]
                .usernameParameter("username")
                .passwordParameter("password")

                
                
                //[인증 성공/실패후 작업할 내용]
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication.getName():" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception:" + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })

//                .successHandler((request, response, authentication) -> {
//                    System.out.println("authentication.getName():" + authentication.getName());
//                    response.sendRedirect("/");
//                })
//                .failureHandler((request, response, exception) -> {
//                    System.out.println("exception:" + exception.getMessage());
//                    response.sendRedirect("/login");
//                })

                //[인증 성공/실패후 이동할 페이지]
                .defaultSuccessUrl("/")
                .failureUrl("/login")

        ;

    }
}
