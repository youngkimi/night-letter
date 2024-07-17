package com.nightletter.domain.member.service;

import static com.nightletter.domain.member.entity.Provider.*;

import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.member.entity.Provider;
import com.nightletter.domain.member.repository.MemberRepository;
import com.nightletter.global.utils.Nickname;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2MemberServiceImpl extends DefaultOAuth2UserService {

	private final MemberRepository memberRepository;

	@Value("${profile.base-url}")
	private String profileBaseUrl;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		OAuth2User oAuth2User = super.loadUser(userRequest);

		String oauthClientName = userRequest.getClientRegistration().getClientName();

		Member member = null;
		String OAuth2Id = null;
		String email = null;
		String nickname = null;
		String profileImgUrl = null;
		Provider provider = null;

		switch (oauthClientName) {
			case "kakao":
				OAuth2Id = "kakao_" + oAuth2User.getAttribute("id");

				member = memberRepository.findMemberByOAuth2Id(OAuth2Id);

				if (member != null) { return member; }

				Map<String, String> kakaoAccountInfo = oAuth2User.getAttribute("kakao_account");
				// Map<String, String> kakaoProfileInfo = oAuth2User.getAttribute("properties");

				int profileRandomNum = ThreadLocalRandom.current().nextInt(1, 31);

				assert kakaoAccountInfo != null;

				email = kakaoAccountInfo.getOrDefault("email", null);
				nickname = Nickname.createRandom();

				profileImgUrl = profileBaseUrl + profileRandomNum + ".webp";
				provider = KAKAO;

				break;
			case "apple":
				break;
		}

		if (provider == null) {
			return null;
		}

		member = Member.builder()
			.OAuth2Id(OAuth2Id)
			.email(email)
			.nickname(nickname)
			.profileImgUrl(profileImgUrl)
			.provider(provider)
			.build();

		member = memberRepository.save(member);

		return member;
	}
}
