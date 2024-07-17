package com.nightletter.global.security.handler.jwt;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.member.repository.MemberRepository;
import com.nightletter.global.exception.CommonErrorCode;
import com.nightletter.global.exception.ResourceNotFoundException;
import com.nightletter.global.exception.ValidationException;
import com.nightletter.global.security.token.AccessToken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtProvider jwtProvider;
	private final MemberRepository memberRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		try {
			Optional.of(parseBearerToken(request))
				.map(jwtProvider::validate)
				.ifPresentOrElse(
					token -> findMemberAndSetSecurityContext(token, request),
					() -> log.info("No bearer token found")
				);
		} catch (Exception e) {
			log.error("Authentication error", e);
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return; // 인증 실패 시 필터 체인을 계속하지 않음
		}
		// Optional.of(parseBearerToken(request))
		// 	.map(jwtProvider::validate)
		// 	.ifPresentOrElse(token -> findMemberAndSetSecurityContext(token, request),
		// 		() -> log.info("No bearer token found")
		// 	);

		filterChain.doFilter(request, response);
	}

	private void findMemberAndSetSecurityContext(AccessToken accessToken ,HttpServletRequest request) {

		memberRepository.findById(accessToken.getMemberId())
			.ifPresentOrElse(
				member -> setSecurityContext(member, accessToken, request),
				() -> {
					throw new ResourceNotFoundException(CommonErrorCode.RESOURCE_NOT_FOUND, "MEMBER IS NOT FOUND");
				}
			);
	}

	private void setSecurityContext(Member member, AccessToken accessToken ,HttpServletRequest request) {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		AbstractAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member, null, List.of(accessToken.getRole()));
		authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		securityContext.setAuthentication(authenticationToken);
		SecurityContextHolder.setContext(securityContext);
	}

	private String parseBearerToken(HttpServletRequest request) {
		return extractTokenFromCookie(request)
				.orElse(extractTokenFromHeader(request)
					.orElseThrow(() -> new ValidationException(CommonErrorCode.INVALID_AUTHORIZATION, "NOT A VALID TOKEN")));
	}

	private static Optional<String> extractTokenFromCookie(HttpServletRequest request) {
		return Optional.ofNullable(request.getCookies())
			.flatMap(cookies -> Arrays.stream(cookies)
				.filter(cookie -> "access-token".equals(cookie.getName()))
				.findFirst()
				.map(Cookie::getValue));
	}

	private static Optional<String> extractTokenFromHeader(HttpServletRequest request) {
		return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
			.filter(authHeader -> authHeader.startsWith("Bearer "))
			.map(authHeader -> authHeader.substring("Bearer ".length()));
	}

}
