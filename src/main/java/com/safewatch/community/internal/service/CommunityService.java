package com.safewatch.community.internal.service;

import com.safewatch.auth.api.AuthFacade;
import com.safewatch.community.internal.domain.Community;
import com.safewatch.community.internal.domain.CommunityAudience;
import com.safewatch.community.internal.domain.CommunityStatus;
import com.safewatch.community.internal.domain.CommunityVisibility;
import com.safewatch.community.internal.dto.CommunityDTO;
import com.safewatch.community.internal.repo.CommunityRepository;
import com.safewatch.common.exceptions.CommunityException;
import com.safewatch.community.internal.util.CreateRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class CommunityService {
    private final AuthFacade authFacade;
    private final CommunityRepository communityRepository;


    @Transactional
    public CommunityDTO createCommunity(Authentication authentication, CreateRequest createRequest) {
        Long userId = authFacade.extractUserId(authentication);

        if (communityRepository.existsByCommunityName(createRequest.communityName())) throw new CommunityException("Community by that name already exists choose another name.");

        CommunityVisibility communityVisibility;
        CommunityAudience communityAudience;

        try {
            communityVisibility = CommunityVisibility.valueOf(createRequest.communityVisibility().toUpperCase());
        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("visibility option not valid.");
        }

        try {
            communityAudience = CommunityAudience.valueOf(createRequest.communityAudience().toUpperCase());
        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("audience option not valid.");
        }

        Community community = new Community();
        community.setCommunityVisibility(communityVisibility);
        community.setCommunityAudience(communityAudience);
        community.setAdminId(userId);
        community.setCommunityName(createRequest.communityName());
        community.setCommunityStatus(CommunityStatus.PENDING_APPROVAL);

        Community createdCommunity = communityRepository.save(community);

        return mapToDTO(createdCommunity);
    }

    public CommunityDTO updateCommunity(Authentication authentication, String communityName, String communityNewName, String audience, String visibility){
        Long adminId = authFacade.extractUserId(authentication);

        if (communityName.equals(communityNewName)) throw new CommunityException("new community name cannot be same as the old community name.");

        if (communityRepository.existsByCommunityName(communityNewName)) throw new CommunityException("Community by that name already exists choose another name.");

        Community community = communityRepository.findByCommunityName(communityName).orElseThrow(() -> new CommunityException("Community not found"));

        if (!Objects.equals(community.getAdminId(), adminId)) throw new CommunityException("Only admins can update community");

        CommunityVisibility communityVisibility;
        CommunityAudience communityAudience;

        try {
            communityVisibility = CommunityVisibility.valueOf(visibility.toUpperCase());
        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("visibility option not valid.");
        }

        try {
            communityAudience = CommunityAudience.valueOf(audience.toUpperCase());
        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("audience option not valid.");
        }

        community.setCommunityVisibility(communityVisibility);
        community.setCommunityAudience(communityAudience);
        community.setCommunityName(communityNewName);
        community.setCommunityStatus(CommunityStatus.PENDING_APPROVAL);
        community.setUpdatedAt(OffsetDateTime.now());

        Community createdCommunity = communityRepository.save(community);

        return mapToDTO(createdCommunity);

    }

    public CommunityDTO getCommunityByCommunityName(Authentication authentication,String communityName){
        Community community = communityRepository.findByCommunityName(communityName).orElseThrow(() -> new CommunityException("Community not found"));

        return mapToDTO(community);
    }

    private CommunityDTO mapToDTO(Community createdCommunity) {
        return new CommunityDTO(
          createdCommunity.getCommunityName(),
                "PENDING APPROVAL"
        );
    }


}
