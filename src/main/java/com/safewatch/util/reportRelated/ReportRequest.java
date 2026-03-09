package com.safewatch.util.reportRelated;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ReportRequest {

    private String title;
    private String description;
    private double longitude;
    private double latitude;
    private String location;
    private String severity;
    private String incidentCategory;
}
