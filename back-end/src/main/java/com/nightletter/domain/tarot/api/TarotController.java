package com.nightletter.domain.tarot.api;

import static com.nightletter.global.common.ResponseDto.*;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nightletter.domain.member.entity.Member;
import com.nightletter.domain.tarot.dto.TarotResponse;
import com.nightletter.domain.tarot.service.TarotService;
import com.nightletter.global.common.CurrentMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v2/tarots")
public class TarotController {

	private final TarotService tarotService;

	@GetMapping("/future")
	public ResponseEntity<TarotResponse> findFutureTarot(@CurrentMember Member member) {
		TarotResponse futureTarot = tarotService.findFutureTarot(member);
		return ResponseEntity.status(HttpStatus.OK).body(futureTarot);
	}

	@GetMapping("/past")
	public ResponseEntity<?> findPastTarot(@CurrentMember Member member) {

		return tarotService.getPastTarot(member)
			.map(ResponseEntity::ok)
			.orElse(ResponseEntity.notFound().build());
	}

	@GetMapping("/present")
	public ResponseEntity<?> findNowTarot(@CurrentMember Member member) {

		return tarotService.getNowTarot(member).map(ResponseEntity::ok)
			.orElse(ResponseEntity.notFound().build());
	}

	// TODO REMOVE AFTER TEST
	@GetMapping("/past-test")
	public ResponseEntity<?> findTestPastTarot(@CurrentMember Member member) {

		return tarotService.findPastTarot(member).map(ResponseEntity::ok)
				.orElse(ResponseEntity.notFound().build());
	}

	@PostMapping("/past")
	public ResponseEntity<?> addPastTarot(@CurrentMember Member member) {

		Optional<TarotResponse> response = tarotService.createRandomPastTarot(member);

		if (response.isEmpty())
			return databaseError();
		return ResponseEntity.ok(response);
	}

	@GetMapping("/test")
	public ResponseEntity<?> getFutureTarotTTL(@CurrentMember Member member) {
		return ResponseEntity.ok(tarotService.getFutureTarot(member));
	}

	@PatchMapping("/test-entity")
	public ResponseEntity<?> updateWithNewEntity(@CurrentMember Member member) {
		return ResponseEntity.ok(tarotService.updateWithNewEntity(member));
	}

}
