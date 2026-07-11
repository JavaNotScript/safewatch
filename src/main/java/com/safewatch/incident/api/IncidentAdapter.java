package com.safewatch.incident.api;

import com.safewatch.common.domain.IncidentCategory;
import com.safewatch.common.exceptions.IncidentNotFoundException;
import com.safewatch.common.util.HelperUtility;
import com.safewatch.incident.internal.domain.Incident;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.domain.Status;
import com.safewatch.incident.internal.dto.IncidentDTO;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import com.safewatch.incident.internal.repo.IncidentRepository;
import com.safewatch.common.domain.Media;
import com.safewatch.common.moderation.MediaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class IncidentAdapter implements IncidentFacade{
    private final IncidentRepository incidentRepository;
    private final MediaRepository mediaRepo;


    @Override
    public IncidentDetailsDTO findById(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident not found."));

        List<Media> mediaList = mediaRepo.findByIncidentId(incident.getIncidentId());

        return HelperUtility.convertToDTO(incident,mediaList);
    }

    @Override
    public Page<IncidentDetailsDTO> findAll(Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findAll(pageable);

        if (incidentPage.isEmpty()){
            return new PageImpl<>(List.of(),pageable,incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentPage.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(Media::getIncidentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentPage.getContent()
                .stream()
                .map(i -> HelperUtility.convertToDTO(i,mediaMap.getOrDefault(i.getIncidentId(),List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList,pageable, incidentPage.getNumberOfElements());
    }

    @Override
    public void deleteReport(Long reportId,Long adminId) {
        Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("incident not found"));
        incident.setStatus(Status.REJECTED);
        incident.setReviewedBy(adminId);
        incident.setReviewedAt(LocalDateTime.now());
        incident.setReviewComment("Rejected by admin");
        incidentRepository.save(incident);
    }

    @Override
    public void updateIncidentTransition(Long reportId, Status target, Long adminId, String comment) {
        Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("incident not found"));

        incident.setStatus(target);
        incident.setReviewedBy(adminId);
        incident.setUpdatedAt(LocalDateTime.now());
        incident.setReviewedAt(LocalDateTime.now());
        incident.setReviewComment(comment);

        incidentRepository.save(incident);
    }


    @Override
    public Page<IncidentDetailsDTO> findByUserId(Long userId, Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findByReportedBy(userId,pageable);

        if (incidentPage.isEmpty()){
            return new PageImpl<>(List.of(),pageable,incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentPage.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(Media::getCommentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentPage
                .getContent()
                .stream()
                .map(i -> HelperUtility.convertToDTO(i,mediaMap.getOrDefault(i.getIncidentId(),List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList,pageable,incidentPage.getTotalElements());
    }

    @Override
    public Page<IncidentDetailsDTO> getDeletedIncidents(Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.getDeletedAtIncidents(pageable);

        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream().map(Incident::getIncidentId).toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(Media::getIncidentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    @Override
    public Page<IncidentDetailsDTO> filterByCategory(IncidentCategory category, Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findByIncidentCategory(category, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);
        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(Media::getIncidentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    @Override
    public Page<IncidentDetailsDTO> filterByStatus(Status status, Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findByStatus(status, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);
        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(Media::getIncidentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    @Override
    public Page<IncidentDetailsDTO> filterBySeverity(Severity severity, Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findBySeverity(severity, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);
        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(Media::getIncidentId));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    @Override
    public IncidentDetailsDTO getIncidentReportedBy(Long userId, Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("incident not found"));

        if (!userId.equals(incident.getReportedBy())) {
            throw new IncidentNotFoundException("incident not found");
        }

        List<Media> mediaList = mediaRepo.findByIncidentId(incident.getIncidentId());

        return HelperUtility.convertToDTO(incident,mediaList);
    }

    @Override
    public IncidentDTO getByIncidentId(Long reportId) {
        Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("incident not found"));

        return HelperUtility.convertToDTO(incident);
    }

}
