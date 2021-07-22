package com.example.oauthspringsecurity.service;

import java.util.Collections;
import java.util.Map;

import com.example.oauthspringsecurity.domain.Member;
import com.example.oauthspringsecurity.domain.OAuthAttributes;
import com.example.oauthspringsecurity.domain.UserProfile;
import com.example.oauthspringsecurity.repository.MemberRepository;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class OAuthService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final MemberRepository memberRepository;

    public OAuthService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest); // OAuth 서비스(github, google, naver)에서 가져온 유저 정보를 담고있음

        String registrationId = userRequest.getClientRegistration()
                                           .getRegistrationId(); // OAuth 서비스 이름(github, naver, google)
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                                                  .getUserInfoEndpoint().getUserNameAttributeName();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        UserProfile userProfile = OAuthAttributes.extract(registrationId, attributes);

        Member member = saveOrUpdate(userProfile);

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(member.getRoleKey())),
                attributes,
                userNameAttributeName);
    }

    private Member saveOrUpdate(UserProfile userProfile) {
        Member member = memberRepository.findByOauthId(userProfile.getOauthId())
                                        .map(m -> m.update(userProfile.getName(), userProfile.getEmail(), userProfile.getImageUrl()))
                                        .orElse(userProfile.toMember());
        return memberRepository.save(member);
    }
}
