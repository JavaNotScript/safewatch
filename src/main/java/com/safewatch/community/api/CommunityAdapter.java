package com.safewatch.community.api;

import com.safewatch.common.exceptions.CommunityException;
import com.safewatch.community.internal.domain.Community;
import com.safewatch.community.internal.domain.CommunityStatus;
import com.safewatch.community.internal.dto.CommunityDTO;
import com.safewatch.community.internal.repo.CommunityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CommunityAdapter implements CommunityFacade{
    private final CommunityRepository communityRepository;

    @Override
    public CommunityDTO findByCommunityName(String communityName) {
        Community community = communityRepository.findByCommunityName(communityName).orElseThrow(() -> new CommunityException("Community not found"));

        return mapToDTO(community);
    }

    @Override
    public CommunityDTO updateCommunityStatus(String communityName) {
        Community community = communityRepository.findByCommunityName(communityName).orElseThrow(() -> new CommunityException("Community not found"));

        community.setCommunityStatus(CommunityStatus.ACTIVE);
        communityRepository.save(community);

        return mapToDTO(community);
    }


    private CommunityDTO mapToDTO(Community createdCommunity) {
        return new CommunityDTO(
                createdCommunity.getCommunityName(),
                "Status"+createdCommunity.getCommunityStatus().name()
        );
    }
}
