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

import com.nightletter.domain.member.dto.MemberDetails;
import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.member.repository.MemberRepository;
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

		Optional<String> tokenOptional = parseBearerToken(request);

		// No token found in cookie and header.
		if (tokenOptional.isEmpty()) {
			log.info("No token found, proceeding with the filter chain");
			filterChain.doFilter(request, response);
			return;
		}

		Optional<AccessToken> token = jwtProvider.validate(tokenOptional.get());

		if (token.isEmpty()) {
			log.info("Bearer token is invalid");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		if (! findMemberAndSetSecurityContext(token.get(), request)) {
			log.info("Member not found for the given token");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		log.info("Token parsed well");

		filterChain.doFilter(request, response);
	}

	private boolean findMemberAndSetSecurityContext(AccessToken accessToken, HttpServletRequest request) {
		return memberRepository.findById(accessToken.getMemberId())
			.map(member -> setSecurityContext(member, accessToken, request))
			.orElseGet(() -> {
				log.warn("Member not found for ID: {}", accessToken.getMemberId());
				return false;
			});
	}

	private boolean setSecurityContext(Member member, AccessToken accessToken ,HttpServletRequest request) {
		try {
			SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
			AbstractAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(new MemberDetails(member), null, List.of(accessToken.getRole()));
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			securityContext.setAuthentication(authenticationToken);
			SecurityContextHolder.setContext(securityContext);
			log.info("Security Context Setting supposed to be good!");
			return true;
		} catch (Exception e) {
			log.error("Error setting security context", e);
			return false;
		}
	}

	private Optional<String> parseBearerToken(HttpServletRequest request) {
		return extractTokenFromCookie(request)
				.or(() -> extractTokenFromHeader(request));
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
