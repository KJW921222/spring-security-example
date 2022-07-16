package com.example.springsecurity.controller;

import com.example.springsecurity.config.auth.CustomUserDetails;
import com.example.springsecurity.domain.Member;
import com.example.springsecurity.domain.RoleEnum;
import com.example.springsecurity.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class TestController {

    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping({"/",""})
    public @ResponseBody String index() {
        return "index";
    }

    @GetMapping("/customer")
    @ResponseBody
    public String customer() {
        return "customer";
    }

    @GetMapping("/seller")
    @ResponseBody
    public String seller() {
        return "seller";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/join")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(Member member){
        String encPassword = passwordEncoder.encode(member.getPassword());
        member.setPassword(encPassword);
        member.setRole(RoleEnum.ROLE_CUSTOMER);
        member.setCreatedDate(LocalDateTime.now());
        member.setFailcount(0);
        memberService.join(member);
        return "redirect:/loginForm";
    }

    @GetMapping("/userid")
    @ResponseBody
    public String userid(@AuthenticationPrincipal CustomUserDetails userDetails) {
        return userDetails.getUsername();
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/role")
    @ResponseBody
    public List<String> role(@AuthenticationPrincipal CustomUserDetails userDetails) {
        return userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

}
