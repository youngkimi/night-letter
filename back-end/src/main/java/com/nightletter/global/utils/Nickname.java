package com.nightletter.global.utils;

import java.util.List;
import java.util.Random;

import lombok.Getter;

@Getter
public enum Nickname {
	prefix(List.of("가냘픈", "가는", "가엾은", "가파른", "같은", "거센", "거친", "검은", "게으른", "고달픈", "고른", "고마운", "고운", "고픈", "곧은",
		"괜찮은", "구석진", "굳은", "굵은", "귀여운", "그런", "그른", "그리운", "기다란", "기쁜", "긴", "깊은", "깎아지른", "깨끗한", "나쁜", "나은",
		"난데없는", "날랜", "날카로운", "낮은", "너그러운", "너른", "널따란", "넓은", "네모난", "노란", "높은", "누런", "눅은", "느닷없는", "느린", "늦은",
		"다른", "더러운", "더운", "덜된", "동그란", "돼먹잖은", "된", "둥그런", "둥근", "뒤늦은", "드문", "딱한", "때늦은", "뛰어난", "뜨거운", "막다른",
		"많은", "매운", "먼", "멋진", "메마른", "메스꺼운", "모난", "못난", "못된", "못생긴", "무거운", "무딘", "무른", "무서운", "미끄러운", "미운",
		"바람직한", "반가운", "밝은", "밤늦은", "보드라운", "보람찬", "부드러운", "부른", "붉은", "비싼", "빠른", "빨간", "뻘건", "뼈저린", "뽀얀", "뿌연",
		"새로운", "서툰", "섣부른", "설운", "성가신", "센", "수줍은", "쉬운", "스스러운", "슬픈", "시원찮은", "싫은", "싼", "쌀쌀맞은", "쏜살같은", "쓰디쓴",
		"쓰린", "쓴", "아니꼬운", "아닌", "아름다운", "아쉬운", "아픈", "안된", "안쓰러운", "안타까운", "않은", "알맞은", "약빠른", "약은", "얇은", "얕은",
		"어두운", "어려운", "어린", "언짢은", "엄청난", "없는", "여문", "열띤", "예쁜", "올바른", "옳은", "외로운", "우스운", "의심스런", "이른", "익은",
		"있는", "작은", "잘난", "잘빠진", "잘생긴", "재미있는", "적은", "젊은", "점잖은", "조그만", "좁은", "좋은", "주제넘은", "줄기찬", "즐거운", "지나친",
		"지혜로운", "질긴", "짓궂은", "짙은", "짠", "짧은", "케케묵은", "큰", "탐스러운", "턱없는", "푸른", "한결같은", "흐린", "희망찬", "흰", "힘겨운")),
	suffix(List.of("광대", "마법사", "여사제", "여황제", "황제", "교황", "연인", "전차", "힘", "은둔자", "정의", "매달린 사람", "죽음", "절제", "악마",
		"탑", "별", "달", "태양", "심판", "세계"));

	private final static Random random = new Random();
	private final List<String> names;

	Nickname(List<String> names) {
		this.names = names;
	}

	public static String createRandom() {
		int prefixIdx = random.nextInt(prefix.names.size());
		int suffixIdx = random.nextInt(suffix.names.size());
		return prefix.getNames().get(prefixIdx) + " " + suffix.getNames().get(suffixIdx);
	}
}
