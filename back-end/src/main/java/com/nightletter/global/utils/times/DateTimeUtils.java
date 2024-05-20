package com.nightletter.global.utils.times;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.TimeZone;

public class DateTimeUtils {

	public static LocalDateTime nowFromZone() {
		return ZonedDateTime.now(ZoneId.of("Asia/Seoul")).toLocalDateTime();
	}

	public static Instant tokenExpireTime() {
		System.out.println("TOKEN EXPIRE TIME : " + LocalDateTime.now());
		return nowFromZone().plusMinutes(60).toInstant(ZoneOffset.of("+09:00"));
	}
}
