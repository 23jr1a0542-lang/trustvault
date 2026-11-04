
package com.Trustvault.system.controller;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.Trustvault.system.AuditLog;
import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.AuditLogRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class AdminDashboardController {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("dd-MM-yyyy hh:mm:ss a");

    private final Useraccountrepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final DocumentRepository documentRepository;

    public AdminDashboardController(
            Useraccountrepository userRepository,
            AuditLogRepository auditLogRepository,
            DocumentRepository documentRepository) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.documentRepository = documentRepository;
    }

    /*
     * Builds the live overview (statistics, latest uploads and recent
     * activity). Everything is read from the database on every request;
     * nothing is cached in the session, a field or a model attribute.
     */
    private String buildLiveOverview() {

        long documentCount = documentRepository.count();
        long accountCount = userRepository.count();
        long auditCount = auditLogRepository.count();

        List<Document> latestDocuments =
                documentRepository.findTop10ByOrderByUploadedAtDescIdDesc();
        List<AuditLog> recentLogs =
                auditLogRepository.findTop10ByOrderByTimestampDescIdDesc();

        StringBuilder html = new StringBuilder();

        html.append("<section class=\"stats\">")
                .append("<div class=\"stat\"><span>Total Documents</span>")
                .append("<strong id=\"statDocuments\">")
                .append(documentCount).append("</strong></div>")
                .append("<div class=\"stat\"><span>Total Accounts</span>")
                .append("<strong id=\"statAccounts\">")
                .append(accountCount).append("</strong></div>")
                .append("<div class=\"stat\"><span>Audit Events</span>")
                .append("<strong id=\"statAudit\">")
                .append(auditCount).append("</strong></div>")
                .append("</section>");

        html.append("<section class=\"panel\"><h2>Latest Uploads</h2>");
        html.append("<table id=\"latestUploads\"><thead><tr>")
                .append("<th>File</th><th>Owner</th><th>Category</th>")
                .append("<th>Uploaded</th></tr></thead><tbody>");

        if (latestDocuments.isEmpty()) {
            html.append("<tr><td colspan=\"4\">No documents yet.</td></tr>");
        }

        for (Document document : latestDocuments) {
            html.append("<tr><td>")
                    .append(escapeHtml(document.getFileName()))
                    .append("</td><td>")
                    .append(escapeHtml(document.getOwner() == null
                            ? "" : document.getOwner().getUsername()))
                    .append("</td><td>")
                    .append(escapeHtml(document.getCategory()))
                    .append("</td><td>")
                    .append(escapeHtml(document.getUploadedAt() == null
                            ? "" : document.getUploadedAt().format(TIME_FORMAT)))
                    .append("</td></tr>");
        }

        html.append("</tbody></table></section>");

        html.append("<section class=\"panel\"><h2>Recent Activity</h2>");
        html.append("<table id=\"recentActivity\"><thead><tr>")
                .append("<th>Time</th><th>User</th><th>Role</th>")
                .append("<th>Action</th><th>Target</th><th>Details</th>")
                .append("<th>Result</th></tr></thead><tbody>");

        if (recentLogs.isEmpty()) {
            html.append("<tr><td colspan=\"7\">No activity recorded yet.</td></tr>");
        }

        for (AuditLog log : recentLogs) {
            html.append("<tr><td>")
                    .append(escapeHtml(log.getTimestamp() == null
                            ? "" : log.getTimestamp().format(TIME_FORMAT)))
                    .append("</td><td>")
                    .append(escapeHtml(log.getUsername()))
                    .append("</td><td>")
                    .append(escapeHtml(log.getActorRole() == null
                            ? "-" : log.getActorRole()))
                    .append("</td><td>")
                    .append(escapeHtml(log.getAction()))
                    .append("</td><td>")
                    .append(escapeHtml(log.getTarget() == null
                            ? "-" : log.getTarget()))
                    .append("</td><td>")
                    .append(escapeHtml(log.getDetails()))
                    .append("</td><td>")
                    .append(escapeHtml(log.getResult()))
                    .append("</td></tr>");
        }

        html.append("</tbody></table></section>");

        return html.toString();
    }

    private boolean isAdmin(Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getName())) {
            return false;
        }

        Optional<Useraccount> user =
                userRepository.findByUsername(authentication.getName());

        return user.isPresent()
                && "ADMIN".equalsIgnoreCase(user.get().getRole())
                && user.get().isEnabled();
    }

    /*
     * Returns account information for the Admin dashboard.
     * Password hashes are never included in the response.
     */
    @GetMapping("/api/admin/users")
    @ResponseBody
    public Map<String, Object> getAdminUsers(
            Authentication authentication) {

        Map<String, Object> response = new LinkedHashMap<>();

        if (!isAdmin(authentication)) {
            response.put("error", "Administrator access required");
            response.put("users", List.of());
            return response;
        }

        List<Map<String, Object>> users = userRepository.findAll()
                .stream()
                .map(user -> {
                    Map<String, Object> item = new LinkedHashMap<>();

                    item.put("username", user.getUsername());
                    item.put("role", user.getRole());
                    item.put("enabled", user.isEnabled());

                    return item;
                })
                .toList();

        response.put("users", users);
        return response;
    }

    /*
     * Existing Admin dashboard page.
     */
    @GetMapping("/admin")
    @ResponseBody
    public String adminDashboard(Authentication authentication) {

        if (!isAdmin(authentication)) {
            return """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport"
                              content="width=device-width, initial-scale=1">
                        <title>Access Denied</title>
                    </head>
                    <body>
                        <h2>Access denied</h2>
                        <p>Only active administrators can open this page.</p>
                        <a href="/">Return to Home</a>
                    </body>
                    </html>
                    """;
        }

        String username = escapeHtml(authentication.getName());

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1">
                          <meta http-equiv="refresh" content="15">
                    <title>TrustVault Admin Dashboard</title>

                    <style>
                        * {
                            box-sizing: border-box;
                        }

                        body {
                            font-family: Arial, sans-serif;
                            background: #f3f5f9;
                            color: #202b3c;
                            margin: 0;
                            padding: 30px;
                        }

                        .container {
                            max-width: 1100px;
                            margin: auto;
                        }

                        header {
                            background: #183b70;
                            color: white;
                            padding: 28px;
                            border-radius: 12px;
                            margin-bottom: 24px;
                        }

                        header h1 {
                            margin-top: 0;
                        }

                        .user-info {
                            font-size: 14px;
                            color: #e1eaff;
                        }

                        .cards {
                            display: grid;
                            grid-template-columns:
                                repeat(auto-fit, minmax(220px, 1fr));
                            gap: 18px;
                        }

                        .card {
                            background: white;
                            padding: 24px;
                            border-radius: 12px;
                            box-shadow: 0 3px 12px #00000012;
                            min-height: 220px;
                        }

                        .card h2 {
                            font-size: 20px;
                            margin-top: 0;
                        }

                        .card p {
                            line-height: 1.5;
                        }

                        .card a {
                            display: inline-block;
                            margin-top: 10px;
                            color: #183b70;
                            font-weight: bold;
                            text-decoration: underline;
                        }

                        .card a:hover {
                            color: #3459d5;
                        }

                        .status {
                            color: #667085;
                            font-size: 14px;
                        }

                        .stats {
                            display: grid;
                            grid-template-columns:
                                repeat(auto-fit, minmax(160px, 1fr));
                            gap: 14px;
                            margin-bottom: 18px;
                        }

                        .stat {
                            background: white;
                            padding: 16px 20px;
                            border-radius: 12px;
                            box-shadow: 0 3px 12px #00000012;
                        }

                        .stat span {
                            display: block;
                            color: #667085;
                            font-size: 13px;
                        }

                        .stat strong {
                            font-size: 26px;
                            color: #183b70;
                        }

                        .panel {
                            background: white;
                            padding: 20px 24px;
                            border-radius: 12px;
                            box-shadow: 0 3px 12px #00000012;
                            margin-bottom: 18px;
                            overflow-x: auto;
                        }

                        .panel h2 {
                            font-size: 18px;
                            margin-top: 0;
                        }

                        .panel table {
                            width: 100%;
                            border-collapse: collapse;
                            font-size: 13px;
                        }

                        .panel th, .panel td {
                            padding: 9px 10px;
                            text-align: left;
                            border-bottom: 1px solid #edf1f6;
                            overflow-wrap: anywhere;
                        }

                        .footer {
                            margin-top: 24px;
                        }

                        .footer a {
                            color: #183b70;
                        }

                        @media (max-width: 600px) {
                            body {
                                padding: 15px;
                            }

                            header {
                                padding: 20px;
                            }
                        }
                    </style>
                </head>

                <body>
                    <div class="container">

                        <header>
                            <h1>TrustVault</h1>
                            <h2>Administrator Dashboard</h2>
                            <p>
                                Manage users and access your document system.
                            </p>
                            <p class="user-info">
    Logged in as: <strong>""" + username + """
    </strong>
</p>
                        </header>

                        """ + buildLiveOverview() + """
                        <div class="cards">

                            <section class="card">
                                <h2>User Management</h2>
                                <p>
                                    Create Viewer accounts and manage
                                    account status.
                                </p>
                                <a href="/admin/users">Manage Users</a>
                            </section>

                            <section class="card">
                                <h2>Document Management</h2>
                                <p>
                                    Open the document dashboard to view
                                    authorized documents and upload files.
                                </p>
                                <a href="/documents">View Documents</a>
                            </section>

                            <section class="card">
                                <h2>Permissions</h2>
                                <p>
                                    Access follows each user's role and
                                    document-sharing permissions.
                                </p>
                                <p class="status">
                                    Permission changes must be enforced
                                    by the backend.
                                </p>
                            </section>

                            <section class="card">
                                <h2>Audit Logs</h2>
                                <p>
                                    Review recorded user activity and
                                    administrative actions.
                                </p>
                                <a href="/admin/audit-logs">
                                    View Audit Logs
                                </a>
                            </section>

                        </div>

                        <div class="footer">
                            <a href="/">Back to Home</a>
                        </div>

                    </div>
                </body>
                </html>
                """;
    }

    private String escapeHtml(String value) {

        if (value == null) {
            return "";
        }

        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
