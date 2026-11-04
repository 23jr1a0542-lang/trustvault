
package com.Trustvault.system.document.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.DocumentStorageService;
import com.Trustvault.system.document.Documentpermission;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.Useraccountrepository;
import com.Trustvault.system.service.AuditLogService;

@Controller
public class DocumentController {

    private final DocumentStorageService storageService;
    private final DocumentRepository documentRepository;
    private final Useraccountrepository userRepository;
    private final DocumentPermissionRepository permissionRepository;
    private final AuditLogService auditLogService;

    public DocumentController(
            DocumentStorageService storageService,
            DocumentRepository documentRepository,
            Useraccountrepository userRepository,
            DocumentPermissionRepository permissionRepository,
            AuditLogService auditLogService) {

        this.storageService = storageService;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.permissionRepository = permissionRepository;
        this.auditLogService = auditLogService;
    }

    @GetMapping("/documents")
    @ResponseBody
    public String documentsPage(Principal principal, CsrfToken csrfToken) {

        Useraccount user = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        String uploadSection;
        List<Document> documents;

        if ("ADMIN".equals(user.getRole())
                || "OWNER".equals(user.getRole())) {

            uploadSection = """
                    <h2>Upload a document</h2>
                    <p class="muted">Choose a file and enter its category.</p>

                    <form action="/documents/upload"
                          method="post"
                          enctype="multipart/form-data">

                        <input type="hidden" name="_csrf" value="%s">

                        <label for="file">Select a file</label>
                        <input type="file" id="file" name="file" required>

                        <label for="category">Category</label>
                        <input type="text" id="category" name="category"
                               placeholder="e.g. Certificates" required>

                        <button type="submit">Upload Document</button>
                    </form>
                    """.formatted(escapeHtml(csrfToken.getToken()));

            documents = "ADMIN".equals(user.getRole())
                    ? documentRepository.findAllByOrderByIdDesc()
                    : documentRepository
                            .findByOwnerUsernameOrderByIdDesc(
                                    user.getUsername());

        } else if ("VIEWER".equals(user.getRole())) {

            uploadSection = """
                    <h2>Read-only access</h2>
                    <p class="notice">
                        You can view and download documents that have been
                        authorized for you. Uploading and deleting are not permitted.
                    </p>
                    """;

            documents = permissionRepository
                    .findByViewerUsernameWithDocument(user.getUsername())
                    .stream()
                    .map(permission -> permission.getDocument())
                    .toList();

        } else {
            throw new AccessDeniedException(
                    "Your role does not have document access.");
        }

        boolean adminView = "ADMIN".equals(user.getRole());

        StringBuilder documentList = new StringBuilder();
        documentList.append("<h2>Saved Documents</h2>");

        if (documents.isEmpty()) {
            documentList.append("""
                    <p class="empty">
                        No documents to display yet.
                    </p>
                    """);
        } else {
            documentList.append("""
                    <table>
                        <thead>
                            <tr>
                                <th>File Name</th>
                                %s
                                <th>Category</th>
                                <th>Uploaded At</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                    """.formatted(adminView ? "<th>Owner</th>" : ""));

            for (Document document : documents) {

                // Owner is only loaded eagerly for Admin/Owner lists; do not
                // touch it for Viewers (lazy proxy, no open session).
                boolean ownedByCurrentUser = adminView
                        && document.getOwner() != null
                        && user.getUsername().equals(
                                document.getOwner().getUsername());

                documentList.append("<tr><td>")
                        .append(escapeHtml(document.getFileName()))
                        .append("</td>");

                if (adminView) {
                    documentList.append("<td>")
                            .append(escapeHtml(document.getOwner() == null
                                    ? ""
                                    : document.getOwner().getUsername()))
                            .append("</td>");
                }

                documentList.append("<td>")
                        .append(escapeHtml(document.getCategory()))
                        .append("</td><td>")
                        .append(escapeHtml(
                                document.getUploadedAt() == null
                                        ? ""
                                        : document.getUploadedAt().toString()))
                        .append("</td><td class=\"actions\">");

                // Admin oversight is read-only for other owners' files.
                if (!adminView || ownedByCurrentUser) {
                    documentList.append(
                            "<a class=\"download-link\" href=\"/documents/")
                            .append(document.getId())
                            .append("/download\">Download</a>");
                } else {
                    documentList.append("View only");
                }

                if ("OWNER".equals(user.getRole())
                        && document.getOwner() != null
                        && user.getUsername().equals(
                                document.getOwner().getUsername())) {

                    documentList.append("""
                            <form class="delete-form"
                                  action="/documents/%d/delete"
                                  method="post"
                                  onsubmit="return confirm('Are you sure you want to delete this document?');">

                                <input type="hidden" name="_csrf" value="%s">
                                <button class="delete-button" type="submit">
                                    Delete
                                </button>
                            </form>
                            """.formatted(
                                    document.getId(),
                                    escapeHtml(csrfToken.getToken())));
                }

                documentList.append("</td></tr>");
            }

            documentList.append("</tbody></table>");
        }

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1">
                    <title>Documents | TrustVault</title>

                    <style>
                        * {
                            box-sizing: border-box;
                        }

                        body {
                            margin: 0;
                            padding: 28px;
                            font-family: Arial, Helvetica, sans-serif;
                            background: #f3f6fb;
                            color: #263449;
                            line-height: 1.6;
                        }

                        .container {
                            width: 100%%;
                            max-width: 1100px;
                            margin: 0 auto;
                        }

                        header {
                            background: #183b70;
                            color: white;
                            padding: 26px;
                            border-radius: 14px;
                            margin-bottom: 22px;
                        }

                        header h1 {
                            margin: 0;
                            font-size: 30px;
                        }

                        header p {
                            margin: 6px 0;
                        }

                        .user-info {
                            margin-top: 18px;
                            color: #e1eaff;
                            overflow-wrap: anywhere;
                        }

                        nav {
                            display: flex;
                            flex-wrap: wrap;
                            gap: 10px;
                            margin-top: 20px;
                        }

                        nav a {
                            display: inline-block;
                            padding: 10px 15px;
                            border-radius: 7px;
                            background: white;
                            color: #183b70;
                            font-weight: bold;
                            text-decoration: none;
                        }

                        nav a:hover {
                            background: #e1eaff;
                        }

                        .panel {
                            background: white;
                            padding: 25px;
                            border-radius: 12px;
                            margin-bottom: 22px;
                            box-shadow: 0 4px 16px #182b4a0c;
                            overflow-x: auto;
                        }

                        h2 {
                            margin-top: 0;
                            color: #183b70;
                            font-size: 22px;
                        }

                        .muted {
                            color: #667085;
                        }

                        .notice {
                            padding: 14px;
                            border-radius: 8px;
                            background: #eef4ff;
                            color: #183b70;
                        }

                        .empty {
                            padding: 18px;
                            border-radius: 8px;
                            background: #f7f9fc;
                            color: #667085;
                        }

                        label {
                            display: block;
                            margin: 16px 0 7px;
                            font-weight: bold;
                        }

                        input[type="file"],
                        input[type="text"] {
                            display: block;
                            width: 100%%;
                            max-width: 460px;
                            padding: 12px;
                            border: 1px solid #cbd5e1;
                            border-radius: 7px;
                            background: white;
                            font: inherit;
                        }

                        input:focus {
                            outline: 2px solid #93b4ff;
                            outline-offset: 1px;
                        }

                        button {
                            margin-top: 18px;
                            padding: 11px 18px;
                            border: none;
                            border-radius: 7px;
                            background: #183b70;
                            color: white;
                            font-weight: bold;
                            cursor: pointer;
                        }

                        button:hover {
                            background: #3459a5;
                        }

                        table {
                            width: 100%%;
                            border-collapse: collapse;
                            margin-top: 16px;
                            background: white;
                        }

                        th,
                        td {
                            padding: 13px;
                            border-bottom: 1px solid #e4e9f0;
                            text-align: left;
                            overflow-wrap: anywhere;
                        }

                        th {
                            background: #183b70;
                            color: white;
                        }

                        tbody tr:nth-child(even) {
                            background: #f7f9fc;
                        }

                        .actions {
                            white-space: normal;
                            min-width: 130px;
                        }

                        .download-link {
                            display: inline-block;
                            margin: 4px 0;
                            color: #174ea6;
                            font-weight: bold;
                        }

                        .delete-form {
                            display: inline-block;
                            margin: 0 0 0 8px;
                        }

                        .delete-button {
                            margin: 0;
                            background: #b42318;
                        }

                        .delete-button:hover {
                            background: #8f1d14;
                        }

                        footer {
                            padding: 12px;
                            text-align: center;
                            color: #667085;
                            font-size: 14px;
                        }

                        @media (max-width: 650px) {
                            body {
                                padding: 12px;
                            }

                            header,
                            .panel {
                                padding: 17px;
                            }

                            header h1 {
                                font-size: 25px;
                            }

                            table {
                                min-width: 650px;
                            }
                        }
                    </style>
                </head>

                <body>
                    <main class="container">
                        <header>
                            <h1>TrustVault</h1>
                            <p>Secure Document Management</p>

                            <p class="user-info">
                                Logged in as: <strong>%s</strong>
                                &nbsp;|&nbsp;
                                Role: <strong>%s</strong>
                            </p>

                            <nav>
                                <a href="/">Back to Dashboard</a>
                                <a href="/documents">My Documents</a>
                            </nav>
                        </header>

                        <section class="panel">
                            %s
                        </section>

                        <section class="panel">
                            %s
                        </section>

                        <footer>
                            TrustVault Secure Document Management System
                        </footer>
                    </main>
                </body>
                </html>
                """.formatted(
                        escapeHtml(user.getUsername()),
                        escapeHtml(user.getRole()),
                        uploadSection,
                        documentList);
    }

    /*
     * API endpoint for the dashboard.
     * Returns only documents the logged-in user is allowed to see.
     */
    @GetMapping("/api/documents")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getApiDocuments(
            Principal principal) {

        Useraccount currentUser = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "User not found"));

        List<Document> documents;

        boolean isAdminUser = "ADMIN".equals(currentUser.getRole());

        if (isAdminUser) {

            // Admin oversight: every persisted document.
            documents = documentRepository.findAllByOrderByIdDesc();

        } else if ("OWNER".equals(currentUser.getRole())) {

            documents = documentRepository
                    .findByOwnerUsernameOrderByIdDesc(
                            currentUser.getUsername());

        } else if ("VIEWER".equals(currentUser.getRole())) {

            documents = permissionRepository
                    .findByViewerUsernameWithDocument(
                            currentUser.getUsername())
                    .stream()
                    .map(Documentpermission::getDocument)
                    .toList();

        } else {
            throw new AccessDeniedException(
                    "Your role does not have document access.");
        }

        List<Map<String, Object>> result = new java.util.ArrayList<>();

        for (Document document : documents) {
            Map<String, Object> item = new LinkedHashMap<>();

            item.put("id", document.getId());
            item.put("name", document.getFileName());
            item.put("category", document.getCategory());
            item.put(
                    "uploaded",
                    document.getUploadedAt() == null
                            ? ""
                            : document.getUploadedAt().toString());

            boolean isShared = "VIEWER".equals(currentUser.getRole());

            if (isAdminUser) {
                String ownerName = document.getOwner() == null
                        ? "" : document.getOwner().getUsername();
                boolean ownDocument =
                        currentUser.getUsername().equals(ownerName);

                item.put("owner", ownerName);
                item.put("canDownload", ownDocument);
                item.put("status",
                        ownDocument ? "Private" : "Owner: " + ownerName);
            } else {
                item.put("status", isShared ? "Shared" : "Private");
            }

            result.add(item);
        }

        return ResponseEntity.ok(result);
    }
@GetMapping("/api/viewers")
@ResponseBody
public ResponseEntity<List<Map<String, String>>> getEligibleViewers(
        Principal principal) {

    Useraccount currentUser = userRepository
            .findByUsername(principal.getName())
            .orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "User not found"));

    if (!"OWNER".equals(currentUser.getRole())) {
        throw new AccessDeniedException(
                "Only document owners can share documents.");
    }

    List<Map<String, String>> viewers = new java.util.ArrayList<>();

    for (Useraccount user : userRepository.findAll()) {
        if ("VIEWER".equals(user.getRole()) && user.isEnabled()) {
            Map<String, String> viewer = new LinkedHashMap<>();
            viewer.put("username", user.getUsername());
            viewers.add(viewer);
        }
    }

    return ResponseEntity.ok(viewers);
}


@PostMapping("/api/documents/{id}/share")
@ResponseBody
public ResponseEntity<Map<String, Object>> shareDocument(
        @PathVariable Long id,
        @RequestParam String viewerUsername,
        Principal principal) {

    Useraccount currentUser = userRepository
            .findByUsername(principal.getName())
            .orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "User not found"));

    if (!"OWNER".equals(currentUser.getRole())) {
        auditLogService.log(
                currentUser.getUsername(),
                "DOCUMENT_SHARE",
                "document id=" + id,
                "Share denied: only owners can share documents",
                "DENIED");
        throw new AccessDeniedException(
                "Only document owners can share documents.");
    }

    Document document = documentRepository.findWithOwnerById(id)
            .orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Document not found"));

    if (!currentUser.getUsername()
            .equals(document.getOwner().getUsername())) {
        auditLogService.log(
                currentUser.getUsername(),
                "DOCUMENT_SHARE",
                AuditLogService.describe(document),
                "Share denied: document belongs to another owner",
                "DENIED");
        throw new AccessDeniedException(
                "You can share only your own documents.");
    }

    Useraccount viewer = userRepository
            .findByUsername(viewerUsername.trim())
            .orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Viewer account not found"));

    if (!"VIEWER".equals(viewer.getRole()) || !viewer.isEnabled()) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Select an active Viewer account.");
    }

    if (permissionRepository.existsByDocumentIdAndViewerUsername(
            id, viewer.getUsername())) {
        return sharingResponse(HttpStatus.CONFLICT,
                "This document is already shared with that Viewer.");
    }

    Documentpermission permission = new Documentpermission();
    permission.setDocument(document);
    permission.setViewer(viewer);
    permissionRepository.save(permission);

    auditLogService.log(
            currentUser.getUsername(),
            "DOCUMENT_SHARE",
            AuditLogService.describe(document),
            "Shared with viewer: " + viewer.getUsername(),
            "SUCCESS");

    return sharingResponse(HttpStatus.OK,
            "Document shared successfully with " + viewer.getUsername() + ".");
}

private ResponseEntity<Map<String, Object>> sharingResponse(
        HttpStatus status, String message) {

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("message", message);

    return ResponseEntity.status(status).body(response);
}

    @PostMapping("/documents/upload")
    @ResponseBody
    public String uploadDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam("category") String category,
            @RequestParam(
                    value = "confirmDuplicate",
                    defaultValue = "false") boolean confirmDuplicate,
            Principal principal,
            CsrfToken csrfToken) throws Exception {

        Useraccount owner = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        if (!"ADMIN".equals(owner.getRole())
                && !"OWNER".equals(owner.getRole())) {

            throw new AccessDeniedException(
                    "You are not allowed to upload documents.");
        }

        if (file.isEmpty()) {
            return messagePage(
                    "No file selected",
                    "Choose a file before uploading.",
                    "/documents",
                    "Back to Documents");
        }

        if (category == null || category.isBlank()) {
            return messagePage(
                    "Category is required",
                    "Enter a category before uploading.",
                    "/documents",
                    "Back to Documents");
        }

        String originalName = file.getOriginalFilename();

        if (originalName == null || originalName.isBlank()) {
            return messagePage(
                    "Invalid file name",
                    "Please select a valid file.",
                    "/documents",
                    "Back to Documents");
        }

        String fileName = java.nio.file.Paths
                .get(originalName)
                .getFileName()
                .toString();

        if (fileName.isBlank() || fileName.contains("..")) {
            return messagePage(
                    "Invalid file name",
                    "The selected file name is not valid.",
                    "/documents",
                    "Back to Documents");
        }

        boolean duplicate = documentRepository
                .existsByFileNameIgnoreCaseAndOwnerUsername(
                        fileName,
                        owner.getUsername());

        if (duplicate && !confirmDuplicate) {

            String safeFileName = escapeHtml(fileName);
            String safeCategory = escapeHtml(category.trim());
            String safeToken = escapeHtml(csrfToken.getToken());

            return """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport"
                              content="width=device-width, initial-scale=1">
                        <title>Duplicate File | TrustVault</title>
                        <style>
                            * { box-sizing: border-box; }
                            body {
                                margin: 0;
                                padding: 24px;
                                font-family: Arial, sans-serif;
                                background: #f3f6fb;
                                color: #263449;
                            }
                            .panel {
                                max-width: 650px;
                                margin: 50px auto;
                                padding: 28px;
                                background: white;
                                border-radius: 12px;
                                box-shadow: 0 4px 18px #182b4a12;
                            }
                            h1 { color: #183b70; }
                            .notice {
                                padding: 14px;
                                background: #fff4e5;
                                border-radius: 8px;
                            }
                            label {
                                display: block;
                                margin: 16px 0 8px;
                                font-weight: bold;
                            }
                            input[type="file"] {
                                width: 100%%;
                                padding: 10px;
                                border: 1px solid #cbd5e1;
                                border-radius: 6px;
                            }
                            input[type="hidden"] { display: none; }
                            button {
                                margin-top: 18px;
                                padding: 11px 16px;
                                border: 0;
                                border-radius: 6px;
                                background: #183b70;
                                color: white;
                                font-weight: bold;
                                cursor: pointer;
                            }
                            a { color: #174ea6; }
                        </style>
                    </head>
                    <body>
                        <main class="panel">
                            <h1>Duplicate filename warning</h1>
                            <p class="notice">
                                You already have a document named
                                <strong>%s</strong>.
                            </p>
                            <p>Do you want to upload another copy?</p>

                            <form action="/documents/upload"
                                  method="post"
                                  enctype="multipart/form-data">

                                <input type="hidden" name="_csrf" value="%s">
                                <input type="hidden" name="category" value="%s">
                                <input type="hidden" name="confirmDuplicate"
                                       value="true">

                                <label for="file">
                                    Select the file again to continue
                                </label>
                                <input type="file" id="file" name="file" required>

                                <button type="submit">Continue Upload</button>
                            </form>

                            <p>
                                <a href="/documents">
                                    Cancel and return to Documents
                                </a>
                            </p>
                        </main>
                    </body>
                    </html>
                    """.formatted(
                            safeFileName,
                            safeToken,
                            safeCategory);
        }

        Document saved;

        try {
            String storagePath = storageService.store(file);

            Document document = new Document();
            document.setFileName(fileName);
            document.setCategory(category.trim());
            document.setOwner(owner);
            document.setStoragePath(storagePath);

            saved = documentRepository.save(document);
        } catch (Exception ex) {
            auditLogService.log(
                    owner.getUsername(),
                    "DOCUMENT_UPLOAD",
                    fileName,
                    "Upload failed",
                    "FAILURE");
            throw ex;
        }

        auditLogService.log(
                owner.getUsername(),
                "DOCUMENT_UPLOAD",
                AuditLogService.describe(saved),
                "Uploaded document, category: " + saved.getCategory(),
                "SUCCESS");

        return messagePage(
                "Document uploaded successfully!",
                "Your document has been saved in TrustVault.",
                "/documents",
                "Back to Documents");
    }

    /*
     * Downloads are allowed only for the document owner
     * or a viewer who has been granted permission.
     */
    @GetMapping("/documents/{id}/download")
    @ResponseBody
    public ResponseEntity<Resource> downloadDocument(
            @PathVariable Long id,
            Principal principal) throws IOException {

        Useraccount currentUser = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "User not found"));

        Document document = documentRepository
                .findWithOwnerById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Document not found"));

        boolean isOwner = document.getOwner() != null
                && currentUser.getUsername().equals(
                        document.getOwner().getUsername());

        boolean isAuthorizedViewer =
                "VIEWER".equals(currentUser.getRole())
                && permissionRepository
                        .existsByDocumentIdAndViewerUsername(
                                id, currentUser.getUsername());

        if (!isOwner && !isAuthorizedViewer) {
            auditLogService.log(
                    currentUser.getUsername(),
                    "DOCUMENT_DOWNLOAD",
                    AuditLogService.describe(document),
                    "Unauthorized download attempt",
                    "DENIED");
            throw new AccessDeniedException(
                    "You are not authorized to download this document.");
        }

        try {
            Resource resource = storageService.loadAsResource(
                    document.getStoragePath());

            auditLogService.log(
                    currentUser.getUsername(),
                    "DOCUMENT_DOWNLOAD",
                    AuditLogService.describe(document),
                    isOwner ? "Downloaded own document"
                            : "Downloaded shared document",
                    "SUCCESS");

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(
                            HttpHeaders.CONTENT_DISPOSITION,
                            ContentDisposition.attachment()
                                    .filename(
                                            document.getFileName(),
                                            StandardCharsets.UTF_8)
                                    .build()
                                    .toString())
                    .body(resource);

        } catch (FileNotFoundException ex) {
            auditLogService.log(
                    currentUser.getUsername(),
                    "DOCUMENT_DOWNLOAD",
                    AuditLogService.describe(document),
                    "File missing on server",
                    "FAILURE");
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Document file not found on server.",
                    ex);
        }
    }

    private String messagePage(
            String title,
            String message,
            String link,
            String linkText) {

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1">
                    <title>%s | TrustVault</title>
                    <style>
                        * { box-sizing: border-box; }
                        body {
                            margin: 0;
                            padding: 24px;
                            font-family: Arial, sans-serif;
                            background: #f3f6fb;
                            color: #263449;
                        }
                        .panel {
                            max-width: 650px;
                            margin: 50px auto;
                            padding: 28px;
                            background: white;
                            border-radius: 12px;
                            box-shadow: 0 4px 18px #182b4a12;
                        }
                        h1 { color: #183b70; }
                        a {
                            display: inline-block;
                            margin-top: 12px;
                            padding: 11px 16px;
                            border-radius: 6px;
                            background: #183b70;
                            color: white;
                            text-decoration: none;
                            font-weight: bold;
                        }
                    </style>
                </head>
                <body>
                    <main class="panel">
                        <h1>%s</h1>
                        <p>%s</p>
                        <a href="%s">%s</a>
                    </main>
                </body>
                </html>
                """.formatted(
                        escapeHtml(title),
                        escapeHtml(title),
                        escapeHtml(message),
                        escapeHtml(link),
                        escapeHtml(linkText));
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("'", "&#x27;");
    }
}
