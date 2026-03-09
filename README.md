SafeWatch

SafeWatch is a community-driven incident reporting backend API built with Spring Boot and PostgreSQL.
The system allows users to report incidents, attach images, and provide real-time updates through comments while maintaining moderation workflows and secure authentication.
SafeWatch focuses on scalable backend architecture, clean API design, and secure media handling.

Overview

SafeWatch enables communities to report and track real-world incidents such as:
Traffic congestion
Accidents
Infrastructure failures
Safety hazards

Users can:
Report incidents
Attach images
Comment on incidents
Provide community updates
Track incident status
Moderators can verify and publish incidents to ensure accuracy before public visibility.

Architecture
SafeWatch follows a layered architecture.

Controller Layer
        │
Service Layer
        │
Repository Layer
        │
Database (PostgreSQL)


Responsibilities:

Controllers
Handle HTTP requests
Validate request payloads
Return API responses


Services
Business logic
Authorization checks
Media processing


Repositories
Database queries
Pagination and filtering


DTOs
Structured API responses
Prevent entity exposure

Features
Incident Reporting

Users can create incident reports containing:
Title
Description
Longitude
Latitude
Location
Severity
Category

Optional image attachments

Incidents are initially created with status:
PENDING
Moderation Workflow

Incidents go through a moderation process:
PENDING -> VERIFIED -> PUBLISHED
               |
              REJECTED

Only published incidents are publicly visible.

Comments
Users can comment on published incidents.

Comments allow the community to provide updates such as:
Traffic cleared
Situation worsening
Additional context
Comments support soft deletion.

Media Attachments
Images can be attached to:
Incidents
Comments

Features:
File validation
Size restrictions
Secure storage
Media metadata tracking

Allowed file types:
jpg
png
webp

Maximum size:
3MB

Filtering and Pagination

The API supports filtering incidents by:
Category
Severity
Status
User ownership

Pagination ensures efficient performance even with large datasets.

Tech Stack
Backend
Java 17
Spring Boot
Spring Security
Spring Data JPA
Hibernate

Database
PostgreSQL

Build tool
Maven

Security
JWT Authentication

Database Design

Main entities:
User
Represents a system user.

Fields include:
userId
email
account status flags

Incident
Represents a reported incident.
Important fields:
incidentId
title
description
Longitude
Latitude
location
severity
category
status
reportedAt

Comment
Represents a user comment on an incident.

Supports:
user association
incident association
soft deletion

Media
Represents uploaded images.

Media may belong to:
an incident
a comment

Fields include:
mediaId
storageKey
contentType
sizeBytes
owner

Running the Project
Clone Repository
git clone https://github.com/JavaNotScript/safewatch.git

Navigate to Project
cd safewatch

Build Project
mvn clean install

Run Application
mvn spring-boot:run

Server will start on:
http://localhost:8080

Security

SafeWatch includes several security measures:
JWT authentication
account status validation
media file type validation
upload size restrictions
soft deletes for auditability
