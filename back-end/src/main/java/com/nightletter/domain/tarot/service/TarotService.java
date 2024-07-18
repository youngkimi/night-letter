package com.nightletter.domain.tarot.service;

import java.util.Optional;

import com.nightletter.domain.diary.dto.recommend.EmbedVector;
import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.tarot.dto.TarotResponse;
import com.nightletter.domain.tarot.entity.FutureTarot;
import com.nightletter.domain.tarot.entity.Tarot;
import com.querydsl.core.group.GroupBy;

public interface TarotService {
	Optional<TarotResponse> createRandomPastTarot(Member member);

	Optional<TarotResponse> getPastTarot(Member member);

	Optional<TarotResponse> getNowTarot(Member member);

	Tarot findSimilarTarot(EmbedVector diaryEmbedVector);

	TarotResponse findFutureTarot(Member member);

	Tarot makeRandomTarot(int... ignoreTarotsId);

	Optional<Tarot> findPastTarot(Member member);

	Optional<FutureTarot> getFutureTarot(Member member);

	Optional<FutureTarot>  updateWithNewEntity(Member member);
	Optional<FutureTarot>  updateOnlyFlipped(Integer memberId);

}

