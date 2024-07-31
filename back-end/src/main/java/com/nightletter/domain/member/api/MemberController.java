package com.nightletter.domain.member.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.member.service.MemberService;
import com.nightletter.global.common.CurrentMember;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v2/members")
public class MemberController {

	private final MemberService memberService;

	@GetMapping("/nickname")
	public ResponseEntity<?> getMemberNickname(@CurrentMember Member member) {
		return ResponseEntity.ok(memberService.getMemberNickname(member));
	}

	@PatchMapping("/nickname")
	public ResponseEntity<?> updateMemberNickname(@CurrentMember Member member, @RequestParam String nickname) {
		return ResponseEntity.ok(memberService.updateMemberNickname(member, nickname));
	}

	@DeleteMapping("")
	public ResponseEntity<?> removeMember(@CurrentMember Member member) {
		memberService.deleteMember(member);
		return ResponseEntity.noContent().build();
	}

}
