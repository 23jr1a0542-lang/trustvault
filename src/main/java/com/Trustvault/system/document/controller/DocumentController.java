package com.Trustvault.system.document.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;

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
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class DocumentController {

    private final DocumentStorageService storageService;
    private final DocumentRepository documentRepository;
    private final Useraccountrepository userRepository;
    private final DocumentPermissionRepository permissionRepository;

    public DocumentController(
            DocumentStorageService storageService,
            DocumentRepository documentRepository,
            Useraccountrepository userRepository,
            DocumentPermissionRepository permissionRepository) {
        this.storageService = storageService;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.permissionRepository = permissionRepository;
    }

    @GetMapping("/documents")
    @ResponseBody
    public String documentsPage(
            Principal principal,
            CsrfToken csrfToken) {

        Useraccount user = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                    new IllegalStateException("User not found"));

        String uploadSection = "";
        List<Document> documents = List.of();

        if ("ADMIN".equals(user.getRole())
                || "OWNER".equals(user.getRole())) {

            uploadSection = """
                    <h2>Upload a document</h2>
                    <form action="/documents/upload"
                          method="post"
                          enctype="multipart/form-data">
                        <input type="hidden"
                               name="_csrf"
                               value="%s">
                        <label>Select a file:</label>
                        <input type="file" name="file" required>
                        <br><br>
                        <label>Category:</label>
                        <input type="text" name="category"
                               placeholder="e.g. Certificates" required>
                        <br><br>
                        <button type="submit">Upload</button>
                    </form>
                    """.formatted(escapeHtml(csrfToken.getToken()));

            documents = documentRepository
                    .findByOwnerUsername(user.getUsername());

        } else if ("VIEWER".equals(user.getRole())) {

            uploadSection = """
                    <h2>Read-only access</h2>
                    <p>You can view documents that have been
                       authorized for you. Uploading is not permitted.</p>
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

        StringBuilder documentList = new StringBuilder();

        documentList.append("<h2>Saved Documents</h2>");

        if (documents.isEmpty()) {
            documentList.append("<p>No documents to display.</p>");
        } else {
            documentList.append("""
                    <table border="1" cellpadding="8">
                    <tr>
                        <th>File Name</th>
                        <th>Category</th>
                        <th>Uploaded At</th>
                        <th>Action</th>
                    </tr>
                    """);

            for (Document document : documents) {
                documentList.append("<tr><td>")
                        .append(escapeHtml(document.getFileName()))
                        .append("</td><td>")
                        .append(escapeHtml(document.getCategory()))
                        .append("</td><td>")
                        .append(escapeHtml(
                                document.getUploadedAt() == null
                                        ? ""
                                        : document.getUploadedAt().toString()))
                        .append("</td><td>")
                        .append("<a href=\"/documents/")
                        .append(document.getId())
                        .append("/download\">Download</a>")
                        .append("</td></tr>");
            }

            documentList.append("</table>");
        }

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>TrustVault Documents</title>
                </head>
                <body>
                    <h1>TrustVault Documents</h1>
                    <p>Logged in as: %s</p>
                    %s
                    %s
                </body>
                </html>
                """.formatted(
                        escapeHtml(user.getUsername()),
                        uploadSection,
                        documentList);
    }

    @PostMapping("/documents/upload")
    @ResponseBody
    public String uploadDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam("category") String category,
            Principal principal) throws Exception {

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
            return """
                    <h2>No file selected</h2>
                    <a href="/documents">Go back</a>
                    """;
        }

        if (category == null || category.isBlank()) {
            return """
                    <h2>Category is required</h2>
                    <a href="/documents">Go back</a>
                    """;
        }

        String storagePath = storageService.store(file);

        Document document = new Document();
        document.setFileName(file.getOriginalFilename());
        document.setCategory(category.trim());
        document.setOwner(owner);
        document.setStoragePath(storagePath);

        documentRepository.save(document);

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Upload Successful</title>
                </head>
                <body>
                    <h2>Document uploaded successfully!</h2>
                    <a href="/documents">Back to Documents</a>
                </body>
                </html>
                """;
    }

    @GetMapping("/documents/{id}/download")
    public ResponseEntity<Resource> downloadDocument(
            @PathVariable Long id,
            Principal principal) throws IOException {

        Useraccount currentUser = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED, "User not found"));

        Document document = documentRepository.findById(id)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "Document not found"));

        boolean isAdmin = "ADMIN".equals(currentUser.getRole());
        boolean isOwner = "OWNER".equals(currentUser.getRole())
                && document.getOwner() != null
                && currentUser.getUsername().equals(document.getOwner().getUsername());
        boolean isAuthorizedViewer = "VIEWER".equals(currentUser.getRole())
                && permissionRepository.existsByDocumentIdAndViewerUsername(
                        id, currentUser.getUsername());

        if (!isAdmin && !isOwner && !isAuthorizedViewer) {
            throw new AccessDeniedException(
                    "You do not have permission to download this document.");
        }

        try {
            Resource resource = storageService.loadAsResource(document.getStoragePath());

            String rawFileName = document.getFileName();
            String safeFileName = (rawFileName == null || rawFileName.isBlank())
                    ? "document"
                    : rawFileName;

            ContentDisposition disposition = ContentDisposition.attachment()
                    .filename(safeFileName, StandardCharsets.UTF_8)
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);
        } catch (FileNotFoundException e) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Document file not found on server.");
        } catch (SecurityException e) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Access to the requested file path is forbidden.");
        }
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
