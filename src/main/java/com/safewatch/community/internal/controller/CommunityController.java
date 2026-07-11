package com.safewatch.community.internal.controller;

import com.safewatch.community.internal.dto.CommunityDTO;
import com.safewatch.community.internal.service.CommunityService;
import com.safewatch.community.internal.util.CreateRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/community")
@RequiredArgsConstructor
public class CommunityController {
    private final CommunityService communityService;

    @PostMapping("/create")
    public ResponseEntity<CommunityDTO> createCommunity(Authentication authentication, @RequestBody CreateRequest createRequest){
        return ResponseEntity.ok(communityService.createCommunity(authentication,createRequest));
    }

    @PutMapping("/update")
    public ResponseEntity<CommunityDTO> updateCommunity(Authentication authentication,@RequestBody UpdateRequest updateRequest){
        return ResponseEntity.ok(communityService.updateCommunity(authentication,updateRequest.communityName(), updateRequest.communityNewName(), updateRequest.visibility(), updateRequest.audience()));
    }

}
