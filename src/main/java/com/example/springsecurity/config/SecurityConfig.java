package com.example.springsecurity.config;

import com.example.springsecurity.config.auth.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /**
         * csrf 보호를 사용하지 않는다
         */
        http.csrf().disable();

        /**
        * 리소스에 대한 권한 설정을 한다. 순서를 따지는데, 범위가 작은 리소스부터 앞에 위치시켜야 한다.
        * antMatchers : 특정 리소스에 대한 권한 설정
        * permitAll : 인증 없이 접근 가능
        * authenticated : 인증된 사용자만 접근 가능
        * hasAnyRole, hasRole : 해당 권한을 가지는 사용자만 접근 가능
        * anyRequest : antMatchers로 설정한 리소스를 제외한 나머지 리소스들
        * */
        http.authorizeHttpRequests()
                .antMatchers("/loginForm","/join").permitAll()
                .antMatchers("/customer/**").authenticated()
                .antMatchers("/seller/**").hasAnyRole("SELLER","ADMIN")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();

        /**
        * Form Login을 사용하는 로그인에 대한 처리를 설정한다.
        * loginPage : 커스텀 로그인 페이지를 사용할 때 설정한다.
        *             설정하지 않으면 /login 요청을 가로채 스프링 시큐리티가 기본적으로 제공하는 로그인 페이지가 호출된다.
        * usernameParameter : 기본적으로 username이란 파라미터를 id로 인식하는데, id에 대한 파라미터명이 username이 아닐 경우 명시해주어야 한다.
        * passwordParameter : 기본적으로 password이란 파라미터를 패스워드로 인식하는데, 패스워드에 대한 파라미터명이 password가 아닐 경우 명시해주어야 한다.
        * loginProcessingUrl : 로그인 처리를 하는 URL
        * defaultSuccessUrl : 로그인 성공 후 이동할 URL
        * failureUrl : 로그인 실패 후 이동할 URL
        * successHandler : 로그인 성공 후 별도의 처리가 필요할 경우 핸들러를 등록할 수 있다.
        * failureHandler : 로그인 실패 후 별도의 처리가 필요할 경우 핸들러를 등록할 수 있다.
        * */
        http.formLogin()
                .loginPage("/loginForm")
                .usernameParameter("userid")
                .passwordParameter("password")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
//                .failureUrl("/")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//
//                    }
//                })
        ;

        /**
         * 인증/인가 실패에 따른 처리
         * authenticationEntryPoint : 인증 실패 시 처리
         * accessDeniedHandler : 인가 실패 시 처리
         * accessDeniedPage : 인가 실패 시 이동할 URL
         */
//        http.exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//
//                    }
//                })
//                .accessDeniedPage("");

        /**
         * 로그아웃 처리에 대한 설정을 한다.
         * logoutUrl : 로그아웃 처리 URL
         * logoutSuccessUrl : 로그아웃 성공 후 이동할 URL
         * deleteCookies : 로그아웃 후 해당하는 쿠키를 삭제, 여러 개 입력 가능
         */
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID");

        return http.build();
    }
}
