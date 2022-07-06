package com.example.springsecurity.repository;

import com.example.springsecurity.domain.Member;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface MemberRepository {
    void join(Member member);
    Member findByUserid(String userid);
}
