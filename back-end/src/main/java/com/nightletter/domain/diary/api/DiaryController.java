package com.nightletter.domain.diary.api;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nightletter.domain.diary.dto.recommend.RecommendResponse;
import com.nightletter.domain.diary.dto.request.DiaryCreateRequest;
import com.nightletter.domain.diary.dto.request.DiaryDisclosureRequest;
import com.nightletter.domain.diary.dto.request.DiaryListRequest;
import com.nightletter.domain.diary.dto.response.DiaryResponse;
import com.nightletter.domain.diary.dto.response.DiaryScrapResponse;
import com.nightletter.domain.diary.dto.response.GPTResponse;
import com.nightletter.domain.diary.dto.response.TodayDiaryResponse;
import com.nightletter.domain.diary.service.DiaryService;
import com.nightletter.domain.diary.service.GptServiceImpl;
import com.nightletter.domain.tarot.dto.TarotResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v2/diaries")
public class DiaryController {

	private final DiaryService diaryService;
	private final GptServiceImpl gptService;

	@PostMapping("")
	public ResponseEntity<TarotResponse> addDiary(@RequestBody DiaryCreateRequest diaryCreateRequest) {
		TarotResponse tarot = diaryService.createDiary(diaryCreateRequest);
		return ResponseEntity.status(HttpStatus.CREATED).body(tarot);
	}

	@PatchMapping("")
	public ResponseEntity<DiaryResponse> modifyDiary(@RequestBody DiaryDisclosureRequest diaryDisclosureRequest) {

		Optional<DiaryResponse> diary = diaryService.updateDiaryDisclosure(diaryDisclosureRequest);

		return diary
			.map(ResponseEntity::ok)
			.orElseGet(() -> ResponseEntity.badRequest().build());
	}

	@GetMapping("/today")
	public ResponseEntity<?> isTodayDiaryWritten() {

		TodayDiaryResponse response = diaryService.isTodayDiaryWritten();

		return ResponseEntity.ok(
			response
		);
	}

	@PostMapping("/self")
	public ResponseEntity<?> findDiaries(@RequestBody DiaryListRequest diaryListRequest) {
		List<DiaryResponse> response = diaryService.findDiaries(diaryListRequest);

		return ResponseEntity.ok(response);
	}

	@GetMapping("/{diaryId}")
	public ResponseEntity<?> findDiary(@PathVariable Long diaryId) {

		Optional<DiaryResponse> response = diaryService.findDiary(diaryId);

		return response.map(ResponseEntity::ok)
			.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@DeleteMapping("/{diaryId}")
	public ResponseEntity<?> deleteDiary(@PathVariable Long diaryId) {

		return diaryService.deleteDiary(diaryId).map(ResponseEntity::ok)
			.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@PostMapping("/share")
	public ResponseEntity<?> getDiaryShareUrl(@RequestParam Long diaryId) {

		return ResponseEntity.ok().build();
	}

	@GetMapping("/get_comment")
	public ResponseEntity<?> findGptComment() {
		Optional<GPTResponse> response = gptService.findGptComment();
		return response.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}

	@GetMapping("/scrap")
	public ResponseEntity<?> findScraps(@RequestParam Integer page) {
		Page<DiaryScrapResponse> scraps = diaryService.findScrappedRecommends(page);
		return ResponseEntity.status(HttpStatus.OK).body(scraps);
	}

	@PostMapping("/scrap")
	public ResponseEntity<?> scrapDiary(@RequestParam Long diaryId) {
		diaryService.scrapDiary(diaryId);
		return ResponseEntity.status(HttpStatus.OK).build();
	}

	@DeleteMapping("/scrap")
	public ResponseEntity<?> unscrapDiary(@RequestParam Long diaryId) {
		diaryService.unscrapDiary(diaryId);
		return ResponseEntity.status(HttpStatus.OK).build();
	}

	@GetMapping("/recommend")
	public ResponseEntity<?> findTodayRecommendedDiaries() {

		return ResponseEntity.ok(diaryService.findTodayRecommendedDiaries());
	}

}
