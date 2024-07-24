package com.nightletter.global.utils.times;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.TimeZone;

import org.springframework.beans.factory.annotation.Value;

public class DateTimeUtils {

	private static long accessTokenExpirationTime;

	@Value("${jwt.access.expiration}")
	public void setAccessTokenExpirationTime(long value) {
		accessTokenExpirationTime = value;
	}

	public static LocalDateTime nowFromZone() {
		return ZonedDateTime.now(ZoneId.of("Asia/Seoul")).toLocalDateTime();
	}

	public static Instant tokenExpireTime() {
		return LocalDateTime.now().plusSeconds(accessTokenExpirationTime).toInstant(ZoneOffset.of("+09:00"));
	}

	public static LocalDate getToday() {
		return LocalTime.now().isAfter(LocalTime.of(4, 0)) ?
			LocalDate.now() : LocalDate.now().minusDays(1);
	}
}
