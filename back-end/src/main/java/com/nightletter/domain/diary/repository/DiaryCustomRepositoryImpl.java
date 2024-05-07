package com.nightletter.domain.diary.repository;

import static com.nightletter.domain.diary.entity.QDiary.*;
import static com.nightletter.domain.diary.entity.QDiaryTarot.*;
import static com.nightletter.domain.diary.entity.QScrap.*;
import static com.nightletter.domain.member.entity.QMember.*;
import static com.nightletter.domain.tarot.entity.QTarot.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import com.nightletter.domain.diary.dto.request.DiaryListRequest;
import com.nightletter.domain.diary.dto.recommend.RecommendDiaryResponse;
import com.nightletter.domain.diary.dto.response.DiaryScrapResponse;
import com.nightletter.domain.diary.entity.Diary;
import com.nightletter.domain.diary.entity.DiaryOpenType;
import com.nightletter.domain.diary.entity.DiaryTarotType;
import com.nightletter.domain.member.entity.Member;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DiaryCustomRepositoryImpl implements DiaryCustomRepository {

	private static final int PAGE_SIZE = 10;
	private final JPAQueryFactory queryFactory;

	@Override
	public List<RecommendDiaryResponse> findRecommendDiaries(List<Long> diariesId, Member member) {
		List<RecommendDiaryResponse> responses = queryFactory.select(Projections.constructor(RecommendDiaryResponse.class,
				diary.diaryId,
				diary.content,
				tarot.imgUrl
			))
			.from(diary)
			.innerJoin(diary.diaryTarots, diaryTarot)
			.where(diaryTarot.type.eq(DiaryTarotType.NOW))
			.innerJoin(diaryTarot.tarot, tarot)
			.where(diary.diaryId.in(diariesId)
				.and(diary.type.eq(DiaryOpenType.PUBLIC))
				.and(diary.writer.ne(member)))
			.fetch();

		return responses.stream()
			.distinct()
			.collect(Collectors.toList());
	}

	@Override
	public Page<DiaryScrapResponse> findScrappedDiaries(Integer memberId, Integer pageNo) {

		Pageable pageable = PageRequest.of(pageNo, PAGE_SIZE);

		List<DiaryScrapResponse> results = queryFactory
			.select(Projections.constructor(DiaryScrapResponse.class,
				diary.diaryId,
				diary.content,
				tarot.imgUrl,
				scrap.scrappedAt
			))
			.from(member)
			.innerJoin(member.scraps, scrap)
			.innerJoin(scrap.diary, diary)
			.innerJoin(diary.diaryTarots, diaryTarot)
			.where(diaryTarot.type.eq(DiaryTarotType.NOW))
			.innerJoin(diaryTarot.tarot, tarot)
			.orderBy(scrap.scrappedAt.desc())
			.offset(pageable.getOffset())
			.limit(pageable.getPageSize())
			.fetch();

		Long count = Optional.ofNullable(queryFactory
			.select(scrap.countDistinct())
			.from(member)
			.innerJoin(member.scraps, scrap)
			.innerJoin(scrap.diary, diary)
			.fetchOne())
			.orElse(0L);

		return new PageImpl<>(results, pageable, count);
	}

	@Override
	public List<Diary> findDiariesByMember(Member member, DiaryListRequest request) {
		return queryFactory.select(diary)
			.from(diary)
			.where(diary.writer.eq(member)
				.and(diary.date.between(request.getSttDate(), request.getEndDate())))
			.orderBy(diary.date.asc())
			.fetch();
	}
}
