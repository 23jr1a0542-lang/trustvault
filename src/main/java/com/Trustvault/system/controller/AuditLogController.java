
package com.Trustvault.system.controller;

import java.time.format.DateTimeFormatter;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import com.Trustvault.system.AuditLog;
import com.Trustvault.system.Useraccount;
import com.Trustvault.system.repository.AuditLogRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class AuditLogController {

    private final AuditLogRepository auditLogRepository;
    private final Useraccountrepository userRepository;

    public AuditLogController(
            AuditLogRepository auditLogRepository,
            Useraccountrepository userRepository) {
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/admin/audit-logs")
    @ResponseBody
    public String viewAuditLogs(Authentication authentication) {

        // Verify that a user is authenticated.
        if (authentication == null
                || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Access denied");
        }

        // Find the logged-in user's account.
        Useraccount user = userRepository
                .findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.FORBIDDEN, "Access denied"));

        // Only active Admin accounts can view audit logs.
        if (!user.isEnabled()
                || !"ADMIN".equalsIgnoreCase(user.getRole())) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Access denied");
        }

        // Retrieve records with the newest first.
        List<AuditLog> logs =
                auditLogRepository.findAllByOrderByTimestampDesc();

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("dd-MM-yyyy hh:mm:ss a");

        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>");
        html.append("<html><head>");
        html.append("<meta charset='UTF-8'>");
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1'>");
        html.append("<title>TrustVault Audit Logs</title>");

        html.append("<style>");
        html.append("body{font-family:Arial,sans-serif;margin:30px;");
        html.append("background:#f4f6f9;color:#222;}");
        html.append("h1{color:#17365d;}");
        html.append(".container{background:white;padding:20px;");
        html.append("border-radius:8px;overflow-x:auto;}");
        html.append("table{width:100%;border-collapse:collapse;background:white;}");
        html.append("th,td{padding:12px;border:1px solid #ddd;");
        html.append("text-align:left;overflow-wrap:anywhere;}");
        html.append("th{background:#17365d;color:white;}");
        html.append("tr:nth-child(even){background:#f2f2f2;}");
        html.append("a{color:#17365d;}");
        html.append(".success{color:green;font-weight:bold;}");
        html.append(".failure{color:#c62828;font-weight:bold;}");
        html.append("</style>");

        html.append("</head><body>");

        html.append("<h1>TrustVault Audit Logs</h1>");

        html.append("<p>Logged in as: ")
                .append(escapeHtml(authentication.getName()))
                .append("</p>");

        html.append("<p><a href='/admin'>Back to Admin Dashboard</a></p>");

        html.append("<div class='container'>");
        html.append("<table>");
        html.append("<thead><tr>");
        html.append("<th>ID</th>");
        html.append("<th>Username</th>");
        html.append("<th>Action</th>");
        html.append("<th>Details</th>");
        html.append("<th>Result</th>");
        html.append("<th>Timestamp</th>");
        html.append("</tr></thead><tbody>");

        for (AuditLog log : logs) {

            String formattedTimestamp =
                    log.getTimestamp() == null
                            ? "Not available"
                            : log.getTimestamp().format(formatter);

            html.append("<tr>");

            html.append("<td>")
                    .append(log.getId())
                    .append("</td>");

            html.append("<td>")
                    .append(escapeHtml(log.getUsername()))
                    .append("</td>");

            html.append("<td>")
                    .append(escapeHtml(log.getAction()))
                    .append("</td>");

            html.append("<td>")
                    .append(escapeHtml(log.getDetails()))
                    .append("</td>");

            String result = log.getResult();

            String resultClass = "SUCCESS".equalsIgnoreCase(result)
                    ? "success"
                    : "FAILURE".equalsIgnoreCase(result)
                            ? "failure"
                            : "";

            html.append("<td class='")
                    .append(resultClass)
                    .append("'>")
                    .append(escapeHtml(result))
                    .append("</td>");

            html.append("<td>")
                    .append(escapeHtml(formattedTimestamp))
                    .append("</td>");

            html.append("</tr>");
        }

        if (logs.isEmpty()) {
            html.append("<tr>");
            html.append("<td colspan='6'>No audit records found.</td>");
            html.append("</tr>");
        }

        html.append("</tbody></table>");
        html.append("</div>");
        html.append("</body></html>");

        return html.toString();
    }

    // Escape text before displaying database values in HTML.
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
