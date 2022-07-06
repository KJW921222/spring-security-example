package com.example.springsecurity.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;

@Getter @Setter
@ToString
@NoArgsConstructor
public class Member {
    private Long id;
    private String userid;
    private String password;
    private RoleEnum role;
    private LocalDateTime createdDate;
    private long failcount;
}
