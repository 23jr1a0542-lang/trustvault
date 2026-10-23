
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

            documents = documentRepository
                    .findByOwnerUsernameOrderByIdDesc(user.getUsername());

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
                                <th>Category</th>
                                <th>Uploaded At</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
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
                        .append("</td><td class=\"actions\">")
                        .append("<a class=\"download-link\" href=\"/documents/")
                        .append(document.getId())
                        .append("/download\">Download</a>");

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
    public List<Map<String, Object>> getApiDocuments(Principal principal) {

        Useraccount user = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "User not found"));

        String role = user.getRole();
        List<Document> documents;

        if ("OWNER".equals(role) || "ADMIN".equals(role)) {

            documents = documentRepository
                    .findByOwnerUsernameOrderByIdDesc(user.getUsername());

        } else if ("VIEWER".equals(role)) {

            documents = permissionRepository
                    .findByViewerUsernameWithDocument(user.getUsername())
                    .stream()
                    .map(permission -> permission.getDocument())
                    .toList();

        } else {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Your role does not have document access");
        }

        boolean isViewer = "VIEWER".equals(role);

        return documents.stream().map(document -> {
            Map<String, Object> item = new LinkedHashMap<>();

            item.put("id", document.getId());
            item.put("name", document.getFileName());
            item.put("category", document.getCategory());
            item.put(
                    "uploaded",
                    document.getUploadedAt() == null
                            ? ""
                            : document.getUploadedAt().toString());
            item.put("status", isViewer ? "Shared" : "Private");

            return item;
        }).toList();
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

        String storagePath = storageService.store(file);

        Document document = new Document();
        document.setFileName(fileName);
        document.setCategory(category.trim());
        document.setOwner(owner);
        document.setStoragePath(storagePath);

        documentRepository.save(document);

        return messagePage(
                "Document uploaded successfully!",
                "Your document has been saved in TrustVault.",
                "/documents",
                "Back to Documents");
    }


@GetMapping("/documents/{id}/download")
public ResponseEntity<Resource> downloadDocument(
        @PathVariable Long id,
        Principal principal) throws IOException {

    Useraccount currentUser = userRepository
            .findByUsername(principal.getName())
            .orElseThrow(() ->
                    new ResponseStatusException(
                            HttpStatus.UNAUTHORIZED,
                            "User not found"));

    // Load the document together with its owner.
    Document document = documentRepository.findWithOwnerById(id)
            .orElseThrow(() ->
                    new ResponseStatusException(
                            HttpStatus.NOT_FOUND,
                            "Document not found"));

    boolean isAdminOwner = "ADMIN".equals(currentUser.getRole())
            && document.getOwner() != null
            && currentUser.getUsername()
                    .equals(document.getOwner().getUsername());

    boolean isOwner = "OWNER".equals(currentUser.getRole())
            && document.getOwner() != null
            && currentUser.getUsername()
                    .equals(document.getOwner().getUsername());

    boolean isAuthorizedViewer =
            "VIEWER".equals(currentUser.getRole())
            && permissionRepository
                    .existsByDocumentIdAndViewerUsername(
                            id,
                            currentUser.getUsername());

    if (!isAdminOwner && !isOwner && !isAuthorizedViewer) {
        throw new AccessDeniedException(
                "You do not have permission to download this document.");
    }

    try {
        Resource resource = storageService
                .loadAsResource(document.getStoragePath());

        String rawFileName = document.getFileName();
        String safeFileName =
                (rawFileName == null || rawFileName.isBlank())
                        ? "document"
                        : rawFileName;

        ContentDisposition disposition =
                ContentDisposition.attachment()
                        .filename(safeFileName, StandardCharsets.UTF_8)
                        .build();

        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        disposition.toString())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);

    } catch (FileNotFoundException e) {
        throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "Document file not found on server.");

    } catch (SecurityException e) {
        throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Access to the requested file path is forbidden.");
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
