package com.nightletter.domain.tarot.dto;

import com.nightletter.domain.tarot.entity.TarotDirection;
import com.querydsl.core.annotations.QueryProjection;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
public class TarotResponseQuery {
	int id;
	String name;
	String imgUrl;
	String keyword;
	String description;
	TarotDirection dir;

	@QueryProjection
	public TarotResponseQuery(int id, String name, String imgUrl, String keyword, String description,
		TarotDirection dir) {
		this.id = id;
		this.name = name;
		this.imgUrl = imgUrl;
		this.keyword = keyword;
		this.description = description;
		this.dir = dir;
	}
}
