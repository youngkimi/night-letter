package com.nightletter.domain.member.service;

import com.nightletter.domain.member.dto.MemberNicknameResponse;
import com.nightletter.domain.member.entity.Member;

public interface MemberService {

	public MemberNicknameResponse getMemberNickname(Member member);
	public MemberNicknameResponse updateMemberNickname(Member member, String nickname);

	public void deleteMember(Member member);
}
