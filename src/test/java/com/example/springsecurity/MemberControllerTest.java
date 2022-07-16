package com.example.springsecurity;

import com.example.springsecurity.domain.Member;
import com.example.springsecurity.domain.RoleEnum;
import com.example.springsecurity.repository.MemberRepository;
import com.example.springsecurity.service.MemberService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.LocalDateTime;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class MemberControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private MemberRepository memberRepository;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @DisplayName("로그인 성공 테스트")
    @Test
    public void loginSuccess() throws Exception {
        String userid = "kjw";
        String password = "1234";

        mockMvc.perform(formLogin("/login")
                        .user("userid", userid)
                        .password(password))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated())
                .andDo(print());
    }

    @DisplayName("로그인 실패 테스트")
    @Test
    public void loginFail() throws Exception {
        String userid = "kjw";
        String password = "1111";

        mockMvc.perform(formLogin("/login")
                        .user("userid", userid).password(password))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/loginForm?error"));
    }

    @DisplayName("admin 권한인 사용자가 admin 페이지에 접근")
    @Test
    @WithMockUser(username = "test", roles = "ADMIN")
    public void AccessAdminSuccess() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @DisplayName("admin 권한이 아닌 사용자가 admin 페이지에 접근")
    @Test
    @WithMockUser(username = "test", roles = "CUSTOMER")
    public void AccessAdminFail() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().isForbidden())
                .andDo(print());
    }


}
