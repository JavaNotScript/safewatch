package com.safewatch.services;

import com.safewatch.DTOs.IncidentDetailsDTO;
import com.safewatch.DTOs.MediaDTO;
import com.safewatch.exceptions.IncidentNotFoundException;
import com.safewatch.exceptions.InvalidIncidentException;
import com.safewatch.models.*;
import com.safewatch.repositories.CurrentUserRepository;
import com.safewatch.repositories.IncidentRepository;
import com.safewatch.repositories.MediaRepository;
import com.safewatch.util.HelperUtility;
import com.safewatch.util.reportRelated.ReportRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class IncidentService {
    private final IncidentRepository incidentRepository;
    private final CurrentUserRepository userRepository;
    private final MediaRepository mediaRepo;
    private final Logger logger = LoggerFactory.getLogger(IncidentService.class);

    public Page<IncidentDetailsDTO> getAllReports() {
        logger.info("Attempting to retrieve all incident reports");

        Pageable pageable = PageRequest.of(0, 10, Sort.by("reportedAt").ascending());

        Page<Incident> incidentPage = incidentRepository.findAllVisibleReports(Status.PUBLISHED, pageable);

        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream().map(Incident::getIncidentId).toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentIdAndDeletedAtIsNull(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream().map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of()))).toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public IncidentDetailsDTO getReportById(Long incidentId) {
        logger.info("Attempting to retrieve incident report incidentId={} ,", incidentId);

        Incident incident = incidentRepository.findVisibleReportById(incidentId, Status.PUBLISHED).orElseThrow(() -> new IncidentNotFoundException("Incident not found"));
        List<Media> media = mediaRepo.getByIncidentIncidentIdAndDeletedAtIsNull(incidentId);

        return HelperUtility.convertToDTO(incident, media);
    }

    public Page<IncidentDetailsDTO> filterByCategory(String category, int page, int size) {
        logger.info("Filtering incident report by category, category={}", category);

        Pageable pageable = PageRequest.of(page, size, Sort.by("reportedAt").descending());

        IncidentCategory categoryEnum;

        try {
            categoryEnum = IncidentCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.error("Invalid severity enum, category={}", category, e);
            throw new IllegalStateException("No such category of type : " + category);
        }

        Page<Incident> filteredIncident = incidentRepository.findByIncidentCategoryAndStatusAndDeletedAtIsNull(categoryEnum, Status.PUBLISHED, pageable);

        List<Incident> incidentList = filteredIncident.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, filteredIncident.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentIdAndDeletedAtIsNull(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> detailsDTOList = incidentList.stream().map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of()))).toList();

        return new PageImpl<>(detailsDTOList, pageable, filteredIncident.getTotalElements());

    }

    public Page<IncidentDetailsDTO> filterBySeverity(String severity, int page, int size) {
        logger.info("Filtering incident reports severity{}.", severity);
        Pageable pageable = PageRequest.of(page, size, Sort.by("reportedAt").ascending());

        Severity severityEnum;
        try {
            severityEnum = Severity.valueOf(severity.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.error("Invalid severity enum, enum={}", severity, e);
            throw new IllegalArgumentException("No such severity of type " + severity);
        }

        Page<Incident> filteredIncident = incidentRepository.findBySeverityAndStatusAndDeletedAtIsNull(severityEnum, Status.PUBLISHED, pageable);

        List<Incident> incidentList = filteredIncident.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, filteredIncident.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentIdAndDeletedAtIsNull(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream().map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of()))).toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, filteredIncident.getTotalElements());
    }

    public Page<IncidentDetailsDTO> filterByStatus(Long userId, String status, int page, int size) {
        logger.info("Filtering incident report by status. status={}", status);
        Pageable pageable = PageRequest.of(page, size, Sort.by("reportedAt").descending());

        Status statusEnum;
        try {
            statusEnum = Status.valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.error("Invalid severity enum, status={}", status, e);
            throw new IllegalArgumentException("No such status of type " + status);
        }


        Page<Incident> filteredIncident = incidentRepository.findByReportedByUserIdAndDeletedAtIsNull(userId, statusEnum, pageable);
        List<Incident> incidentList = filteredIncident.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, filteredIncident.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream().map(Incident::getIncidentId).toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentIdAndDeletedAtIsNull(incidentIds);
        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream().map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of()))).toList();
        return new PageImpl<>(incidentDetailsDTOList, pageable, filteredIncident.getTotalElements());
    }

    public Page<IncidentDetailsDTO> getMyReports(Long userId) {
        Pageable pageable = PageRequest.of(0, 10, Sort.by("reportedAt").ascending());

        Page<Incident> filteredIncident = incidentRepository.getMyVisibleReports(userId, pageable);

        List<Incident> incidentList = filteredIncident.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, filteredIncident.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentIdAndDeletedAtIsNull(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of()))).toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, filteredIncident.getTotalElements());
    }

    public IncidentDetailsDTO reportIncident(Long userId, ReportRequest request, List<MultipartFile> images) {
        logger.info("Reporting incident: userId={}, severity={}, category={}",
                userId, request.getSeverity(), request.getIncidentCategory());


        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Severity severityEnum;
        IncidentCategory category;

        try {
            severityEnum = Severity.valueOf(request.getSeverity().toUpperCase());
            category = IncidentCategory.valueOf(request.getIncidentCategory().toUpperCase());

        } catch (IllegalArgumentException e) {
            logger.error("Failed to parse enums for incident report by userId={}", userId, e);
            throw new InvalidIncidentException("Invalid severity or category");

        }

        HelperUtility.validateReport(request, severityEnum);

        Incident incident = new Incident();
        incident.setReportedAt(LocalDateTime.now());
        incident.setTitle(request.getTitle().trim());
        incident.setIncidentCategory(category);
        incident.setLongitude(request.getLongitude());
        incident.setLatitude(request.getLatitude());
        incident.setLocation(request.getLocation().trim());
        incident.setStatus(Status.PENDING);
        incident.setSeverity(severityEnum);
        incident.setDescription(request.getDescription().trim());
        incident.setReportedBy(user);

        Incident savedIncident = incidentRepository.save(incident);

        if (images != null && !images.isEmpty()) {
            if (images.size() > 5) throw new InvalidIncidentException("Max 5 images allowed");

            for (MultipartFile file : images) {
                if (file.isEmpty()) continue;

                String contentType = file.getContentType();

                if (contentType == null || !(contentType.equals("image/jpeg") || contentType.equals("image/png") || contentType.equals("image/webp"))) {
                    throw new InvalidIncidentException("Only JPG,PNG,WEBP allowed.");
                }

                if (file.getSize() > 3_000_000) {
                    throw new InvalidIncidentException("Max image size allowed is 3MB");
                }

                String extension = switch (contentType) {
                    case "image/jpeg" -> ".jpg";
                    case "image/png" -> ".png";
                    case "image/webp" -> ".webp";
                    default -> "";
                };

                String fileName = UUID.randomUUID() + extension;
                String storageKey = "incident/" + savedIncident.getIncidentId() + "/" + fileName;

                java.nio.file.Path root = Paths.get("uploads").toAbsolutePath().normalize();
                java.nio.file.Path target = root.resolve(storageKey).normalize();

                if (!target.startsWith(root)) throw new SecurityException("Invalid path");

                try {
                    java.nio.file.Files.createDirectories(target.getParent());
                    file.transferTo(target);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to store image", e);
                }

                Media media = new Media();
                media.setOwner(user);
                media.setIncident(savedIncident);
                media.setStorageKey(storageKey);
                media.setOriginalFilename(file.getOriginalFilename());
                media.setContentType(contentType);
                media.setSizeBytes(file.getSize());

                mediaRepo.save(media);
            }
        }

        List<Media> media = mediaRepo.getByIncidentIncidentIdAndDeletedAtIsNull(savedIncident.getIncidentId());

        logger.info("Report created: id={}, userId={}, status={}", incident.getIncidentId(), userId, incident.getStatus());
        return HelperUtility.convertToDTO(savedIncident, media);
    }

    public IncidentDetailsDTO updateReport(Long userId, Long reportId, ReportRequest request) {
        logger.info("Attempting to update incident report userId={},reportId={}", userId, reportId);
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("user not found"));

        Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + reportId + ", not found"));

        if (!incident.getReportedBy().getEmail().equals(user.getEmail())) {
            throw new InvalidIncidentException("Unable to update incident report.");
        }

        String categoryEnum = IncidentCategory.valueOf(request.getIncidentCategory().toUpperCase()).name();
        String severityEnum = Severity.valueOf(request.getSeverity().toUpperCase()).name();

        incident.setTitle(request.getTitle());
        incident.setDescription(request.getDescription());
        incident.setLocation(request.getLocation());
        incident.setIncidentCategory(IncidentCategory.valueOf(categoryEnum));
        incident.setSeverity(Severity.valueOf(severityEnum));
        incident.setStatus(Status.PENDING);
        incident.setUpdatedAt(LocalDateTime.now());
        incident.setReportedBy(user);

        Incident savedIncident = incidentRepository.save(incident);
        logger.info("Updated incident report successfully reportId={}, userID={}", savedIncident.getIncidentId(), user.getUserId());
        List<Media> mediaList = mediaRepo.getByIncidentIncidentIdAndDeletedAtIsNull(incident.getIncidentId());
        return HelperUtility.convertToDTO(savedIncident, mediaList);
    }

    public List<MediaDTO> addMediaToReport(Long incidentId, List<MultipartFile> media) {
        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + incidentId + ", not found"));

        if (media != null && !media.isEmpty()) {
            if (media.size() > 5) throw new InvalidIncidentException("Max 5 images allowed.");

            for (MultipartFile file : media) {
                if (file.isEmpty()) continue;

                String contentType = file.getContentType();

                if (contentType == null || !(contentType.equals("image/jpeg") || contentType.equals("image/png") || contentType.equals("image/webp"))) {
                    throw new InvalidIncidentException("Invalid media type. Only JPG,PNG,WEBP allowed.");
                }

                if (file.getSize() > 3_000_000) {
                    throw new InvalidIncidentException("Max image size allowed is 3MB");
                }

                String extension = switch (contentType) {
                    case "image/jpeg" -> ".jpg";
                    case "image/png" -> ".png";
                    case "image/webp" -> ".webp";
                    default -> "";
                };

                String fileName = UUID.randomUUID() + extension;
                String storageKey = "comment/" + incident.getIncidentId() + "/" + fileName;

                Path root = Paths.get("uploads").toAbsolutePath().normalize();
                Path target = root.resolve(storageKey).normalize();

                if (!target.startsWith(root)) throw new SecurityException("Invalid path");

                try {
                    Files.createDirectories(target.getParent());
                    file.transferTo(target);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to store image", e);
                }

                Media medFile = new Media();
                medFile.setIncident(incident);
                medFile.setSizeBytes(file.getSize());
                medFile.setContentType(contentType);
                medFile.setOriginalFilename(fileName);
                medFile.setStorageKey(storageKey);
                medFile.setOwner(incident.getReportedBy());

                mediaRepo.save(medFile);
            }
        }

        List<Media> mediaList = mediaRepo.getByIncidentIncidentIdAndDeletedAtIsNull(incident.getIncidentId());
        return HelperUtility.convertToMediaDTO(mediaList);
    }

    //soft delete to help with auditing
    @Transactional
    public void deleteIncident(Long userId, Long incidentId, String reason) {
        logger.info("Attempting to delete incident report by user_id={}", userId);

        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident with id " + incidentId + " not found"));

        if (incident.getDeletedAt() != null)
            throw new InvalidIncidentException("Incident with id " + incidentId + " does not exist.");

        incident.setDeletedAt(OffsetDateTime.now());
        incident.setDeletedBy(userId);
        incident.setDeletedReason(reason);
        incident.setStatus(Status.DELETED);

        logger.info("deleted_By={} deleted_Reason={}", incident.getDeletedBy(), reason);

        incidentRepository.save(incident);
    }
}
