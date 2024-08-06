package com.nightletter.global.security.handler;

import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import com.nightletter.domain.member.dto.MemberDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.nightletter.domain.member.entity.Member;
import com.nightletter.global.exception.CommonErrorCode;
import com.nightletter.global.exception.InvalidAuthenticationException;
import com.nightletter.global.security.handler.jwt.JwtProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	@Value("${spring.security.provider.response-uri.kakao}")
	private String tokenResponseURI;

	@Value("${jwt.access.expiration}")
	private Long accessTokenExpirationTime;

	private final JwtProvider jwtProvider;

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication
	) {
		// Optional.ofNullable(authentication)
		// 	.map(Authentication::getPrincipal)
		// 	.filter(Member.class::isInstance)
		// 	.map(Member.class::cast)
		// 	.map(member -> jwtProvider.create(member.getMemberId().toString()))
		// 	.map(this::getAccessCookie)
		// 	.ifPresentOrElse(
		// 		cookie -> sendSuccessResponse(response, cookie),
		// 		this::handleAuthenticationFailure
		// 	);

		Optional.of(authentication)
			.map(Authentication::getPrincipal)
			.filter(MemberDetails.class::isInstance)
			.map(MemberDetails.class::cast)
			.map(memberDetails -> jwtProvider.create(memberDetails.getMember().getMemberId().toString()))
			.map(this::getAccessCookie)
			.ifPresentOrElse(
				cookie -> sendSuccessResponse(response, cookie),
				this::handleAuthenticationFailure
			);

	}

	private ResponseCookie getAccessCookie(String token) {
		return ResponseCookie.from("access-token", token)
			.maxAge(Duration.of(accessTokenExpirationTime, ChronoUnit.MILLIS))
			.httpOnly(true)
			.path("/")
			.sameSite("None")
			.secure(true)
			.build();
	}

	private void sendSuccessResponse(HttpServletResponse response, ResponseCookie cookie) {
		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		try {
			response.sendRedirect(tokenResponseURI);
		}
		catch (IOException e) {
			log.error("ERROR SENDING SUCCESS RESPONSE: ", e);
		}
	}

	private void handleAuthenticationFailure() {
			log.error("ERROR PARSING TOKEN");
			throw new InvalidAuthenticationException(CommonErrorCode.INVALID_AUTHENTICATION, "ERROR IN PARSING TOKEN");
	}

}