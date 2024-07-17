package com.nightletter.domain.diary.dto.response;

import java.time.LocalDate;

import com.nightletter.domain.diary.entity.DiaryOpenType;
import com.nightletter.domain.tarot.dto.TarotResponseQuery;

public record DiaryResponseQuery(
	int writerId,
	long diaryId,
	DiaryOpenType type,
	String content,
	String gptComment,
	LocalDate date
	) {

}
