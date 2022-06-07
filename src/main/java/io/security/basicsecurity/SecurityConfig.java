package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //인가 정책
        http
                .authorizeRequests()
                    .anyRequest().authenticated()
        ;

        //인증정책
        http
                .formLogin()
                .permitAll() //위 .loginPage("/loginPage")에 대한 접근권한을 모두에게 주겠다.
//                .loginPage("/loginPage")            //이 설정이 없으면 시큐리티가 제공하는 기본로그인페이지가 보임
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                      System.out.println("authentication.getName():" + authentication.getName());
//                      response.sendRedirect("/");
//                    }
//                })
                .successHandler((request, response, authentication)->{
                    System.out.println("authentication.getName():" + authentication.getName());
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception)->{
                    System.out.println("exception:" + exception.getMessage());
                    response.sendRedirect("/login");
                })

        ;

    }
}
