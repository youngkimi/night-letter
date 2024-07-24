package com.nightletter.domain.member.dto;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.nightletter.domain.member.entity.Member;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class MemberDetails implements UserDetails {

	private final Member member;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(member.getRole().toString()));
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		System.out.println("Member Details Called");
		return member.getMemberId().toString();
	}

	@Override
	public boolean isAccountNonExpired() {
		return false;
	}

	@Override
	public boolean isAccountNonLocked() {
		return false;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return false;
	}

	@Override
	public boolean isEnabled() {
		return false;
	}

	public MemberDetails of(Member member) {
		return new MemberDetails(member);
	}
}
