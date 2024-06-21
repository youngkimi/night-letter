package com.nightletter.global.security.handler.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;

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

@RequiredArgsConstructor
@Component
public class JwtProvider {

	private final MemberRepository memberRepository;

	@Value("${jwt.secret-key}")
	private String secretKey;

	public String create(String memberId) {

		Date expiredDate = Date.from(DateTimeUtils.tokenExpireTime());

		System.out.println("CREATE EXPIRED TIME: " + expiredDate);

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

	// public String validate(String jwt) {
	//
	// 	String subject = null;
	// 	Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	//
	// 	try {
	// 		subject = Jwts.parserBuilder()
	// 			.setSigningKey(key)
	// 			.build()
	// 			.parseClaimsJws(jwt)
	// 			.getBody()
	// 			.getSubject();
	//
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 		return null;
	// 	}
	//
	// 	System.out.println(subject);
	//
	// 	return subject;
	// }

	public AccessToken validate(String jwt) {

		String subject = null;
		String role = null;

		Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

		try {
			Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(jwt)
				.getBody();

			subject = claims.getSubject();

			role = claims.get("role").toString();

			// Object parsedRoles = claims.get("role");
			//
			// List<GrantedAuthority> convertedRoles = null;
			//
			// if (parsedRoles instanceof List<?> roles) {
			//
			// 	if (! roles.stream()
			// 		.allMatch(role -> role instanceof String)) {
			// 		return null;
			// 	}
			//
			// 	convertedRoles = roles.stream()
			// 		.map(role -> new SimpleGrantedAuthority(role.toString()))
			// 		.collect(Collectors.toList());
			// }

			return AccessToken.builder()
				.memberId(Integer.parseInt(subject))
				.role(new SimpleGrantedAuthority(role))
				.build();

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}
}
