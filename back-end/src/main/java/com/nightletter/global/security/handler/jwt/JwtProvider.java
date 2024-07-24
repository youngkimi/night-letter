package com.nightletter.global.security.handler.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.member.repository.MemberRepository;
import com.nightletter.global.exception.CommonErrorCode;
import com.nightletter.global.exception.ResourceNotFoundException;
import com.nightletter.global.security.token.AccessToken;
import com.nightletter.global.utils.times.DateTimeUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtProvider {

	private final MemberRepository memberRepository;

	@Value("${jwt.secret-key}")
	private String secretKey;

	public String create(String memberId) {

		Date expiredDate = Date.from(DateTimeUtils.tokenExpireTime());

		Key key = Keys.hmacShaKeyFor(secretKey.getBytes((StandardCharsets.UTF_8)));

		Member member = memberRepository.findById(Integer.parseInt(memberId))
			.orElseThrow(() -> new ResourceNotFoundException(CommonErrorCode.RESOURCE_NOT_FOUND, "MEMBER NOT FOUND"));

		// Map<String, Object> roles = Map.of("role", List.of("ROLE_MEMBER"));
		Map<String, Object> roles = Map.of("role", member.getRole());

		return Jwts.builder()
			.signWith(key, SignatureAlgorithm.HS256)
			.setSubject(memberId)
			.setIssuedAt(new Date())
			.setExpiration(expiredDate)
			.addClaims(roles)
			.compact();
	}

	public Optional<AccessToken> validate(String jwt) {

		String subject = null;
		String role = null;

		try {
			Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

			Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(jwt)
				.getBody();

			subject = claims.getSubject();

			role = claims.get("role").toString();

			return Optional.of(AccessToken.builder()
				.memberId(Integer.parseInt(subject))
				.role(new SimpleGrantedAuthority(role))
				.build());
		} catch (Exception e) {
			log.error("Invalid key error");
			return Optional.empty();
		}

	}
}
