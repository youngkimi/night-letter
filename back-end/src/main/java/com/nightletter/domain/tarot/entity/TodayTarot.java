package com.nightletter.domain.tarot.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import com.nightletter.domain.tarot.dto.TarotResponse;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
@RedisHash(value = "today-tarot")
public class TodayTarot {

	@Id
	private Integer memberId;
	private TarotResponse pastCard;
	private TarotResponse nowCard;
	private TarotResponse futureCard;

	@TimeToLive
	private Long expiredTime;
}
