package com.yoo.securityStudy.service;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * ⭐️ 특별한 설정 없이도 자동으로 OAuth 로그인시 해당 Service 사용
 * - 상속을 통해 이뤄졌기 떄문이다!
 * ( UserDetailsService의 경우 Interface를 구현했기에 따로 SecurityConfig에서 등록이 필요 했던 것! )
 * */
@Service
@Log4j2
public class OAuth2UserDetailsService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("-------------------------");
        log.info(" OAuth Social Login Service");
        log.info("-------------------------");

        // OAuth에 사용된 Client Name => 현 테스틑 Goolge Social Login이기에 Goole 출력
        log.info("clientName :: {}",userRequest.getClientRegistration().getClientName());
        // id_token 값을 확인 할 수 있다.
        log.info("additionalParameters ::: {}",userRequest.getAdditionalParameters());

        //반환 객요청 : sub, picture, email, email_verified(이메일 확인) 정보를 갖고 있다.
        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("-----------------------------");
        oAuth2User.getAttributes().forEach((k,v)->{
            log.info("Key :: {} ,  Value ::{}",k,v);
        });
        log.info("-----------------------------");

        return super.loadUser(userRequest);
    }
}
