package com.safewatch.community.internal.controller;

import com.safewatch.community.internal.dto.CommunityDTO;
import com.safewatch.community.internal.util.CreateResponse;
import com.safewatch.community.internal.service.CommunityService;
import com.safewatch.community.internal.util.CreateRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/community")
@RequiredArgsConstructor
public class CommunityController {
    private final CommunityService communityService;

    @PostMapping("/create")
    public ResponseEntity<CommunityDTO> createCommunity(Authentication authentication, @RequestBody CreateRequest createRequest){
        return ResponseEntity.ok(communityService.createCommunity(authentication,createRequest));
    }

}
