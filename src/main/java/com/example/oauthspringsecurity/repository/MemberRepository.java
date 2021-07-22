package com.example.oauthspringsecurity.repository;

import java.util.Optional;

import com.example.oauthspringsecurity.domain.Member;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByOauthId(String id);
}
