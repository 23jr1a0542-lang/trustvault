
package com.Trustvault.system.controller;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

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

        if (authentication == null
                || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Access denied");
        }

        Useraccount user = userRepository
                .findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.FORBIDDEN, "Access denied"));

        if (!user.isEnabled()
                || !"ADMIN".equalsIgnoreCase(user.getRole())) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Access denied");
        }

        List<AuditLog> logs =
                auditLogRepository.findAllByOrderByTimestampDescIdDesc();

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("dd-MM-yyyy hh:mm:ss a");

        long successCount = logs.stream()
                .filter(log -> "SUCCESS".equalsIgnoreCase(log.getResult()))
                .count();

        long failureCount = logs.stream()
                .filter(log -> "FAILURE".equalsIgnoreCase(log.getResult()))
                .count();

        StringBuilder html = new StringBuilder();

        html.append("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta http-equiv="refresh" content="15">
                <title>TrustVault | Audit Logs</title>
                <style>
                *{box-sizing:border-box}
                body{margin:0;font-family:Arial,Helvetica,sans-serif;
                    background:#f3f6fb;color:#1e293b}
                .topbar{background:#122746;color:white;padding:18px 5%;
                    display:flex;justify-content:space-between;align-items:center;
                    gap:15px;flex-wrap:wrap}
                .brand{font-size:21px;font-weight:bold;letter-spacing:.3px}
                .brand span{color:#65d6ad}
                .topbar small{color:#d2dced}
                .page{max-width:1450px;margin:30px auto;padding:0 22px}
                .heading{display:flex;justify-content:space-between;
                    align-items:center;gap:15px;flex-wrap:wrap;margin-bottom:22px}
                h1{margin:0 0 8px;font-size:29px;color:#142c4e}
                .subtitle{margin:0;color:#64748b;line-height:1.5}
                .actions{display:flex;gap:10px;flex-wrap:wrap}
                .button{display:inline-block;text-decoration:none;border:0;
                    border-radius:7px;padding:11px 15px;font-weight:bold;
                    cursor:pointer;font-size:14px}
                .primary{background:#173f70;color:white}
                .secondary{background:white;color:#173f70;
                    border:1px solid #d8e1ed}
                .cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));
                    gap:16px;margin-bottom:24px}
                .card{background:white;padding:20px;border-radius:12px;
                    border:1px solid #e4eaf2;box-shadow:0 3px 12px #172b4d08}
                .card-label{color:#64748b;font-size:14px;margin-bottom:12px}
                .card-value{font-size:30px;font-weight:bold;color:#173f70}
                .card-note{font-size:12px;color:#718096;margin-top:7px}
                .panel{background:white;border:1px solid #e1e8f0;
                    border-radius:12px;overflow:hidden}
                .panel-title{padding:20px 22px;border-bottom:1px solid #e7edf4}
                .panel-title h2{margin:0 0 6px;font-size:19px}
                .panel-title p{margin:0;color:#64748b;font-size:13px}
                .filters{padding:16px 20px;display:grid;
                    grid-template-columns:minmax(180px,2fr) minmax(150px,1fr)
                    minmax(150px,1fr);gap:12px;border-bottom:1px solid #e7edf4}
                input,select{width:100%;padding:11px 12px;
                    border:1px solid #cbd5e1;border-radius:7px;
                    background:white;color:#1e293b;font-size:14px}
                input:focus,select:focus{outline:2px solid #93c5fd;
                    border-color:#2563eb}
                .table-wrap{width:100%;overflow-x:auto}
                table{width:100%;border-collapse:collapse;min-width:850px}
                th{background:#f7f9fc;color:#475569;font-size:12px;
                    text-transform:uppercase;letter-spacing:.5px}
                th,td{padding:15px 17px;text-align:left;
                    border-bottom:1px solid #edf1f6;vertical-align:top}
                td{font-size:13px;line-height:1.5;overflow-wrap:anywhere}
                tbody tr:hover{background:#f8fbff}
                .pill{display:inline-block;padding:5px 9px;border-radius:20px;
                    font-size:11px;font-weight:bold;white-space:nowrap}
                .success{background:#dcfce7;color:#166534}
                .failure{background:#fee2e2;color:#991b1b}
                .neutral{background:#e8eef7;color:#334155}
                .empty{text-align:center;padding:35px;color:#64748b}
                .footer{padding:14px 20px;color:#64748b;font-size:12px;
                    display:flex;justify-content:space-between;gap:12px;
                    flex-wrap:wrap}
                @media(max-width:700px){
                    .page{margin:22px auto;padding:0 12px}
                    .cards{grid-template-columns:1fr}
                    .filters{grid-template-columns:1fr}
                    h1{font-size:24px}
                    .topbar{padding:16px 18px}
                }
                </style>
                </head>
                <body>
                <header class="topbar">
                    <div class="brand">Trust<span>Vault</span></div>
                    <small>Security &amp; Activity Monitoring</small>
                </header>
                <main class="page">
                    <section class="heading">
                        <div>
                            <h1>Audit Logs</h1>
                            <p class="subtitle">Review recorded activity and security events.</p>
                            <p class="subtitle">Logged in as: """);

        html.append(escapeHtml(authentication.getName()));

        html.append("""
                            </p>
                        </div>
                        <div class="actions">
                            <div class="actions">
<a class="button primary" href="/">Back to Main Page</a>
                        </div>
                    </section>
                    <section class="cards">
                        <div class="card">
                            <div class="card-label">Total Recorded Events</div>
                            <div class="card-value">""")
                .append(logs.size())
                .append("""
                            </div>
                            <div class="card-note">All records currently available</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Successful Events</div>
                            <div class="card-value">""")
                .append(successCount)
                .append("""
                            </div>
                            <div class="card-note">Records marked SUCCESS</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Failed Events</div>
                            <div class="card-value">""")
                .append(failureCount)
                .append("""
                            </div>
                            <div class="card-note">Records marked FAILURE</div>
                        </div>
                    </section>
                    <section class="panel">
                        <div class="panel-title">
                            <h2>Activity History</h2>
                            <p>Newest events appear first. Search and filters apply to the displayed records.</p>
                        </div>
                        <div class="filters">
                            <input id="search" type="search"
                                placeholder="Search username, action or details..."
                                aria-label="Search audit logs">
                            <select id="actionFilter" aria-label="Filter by action">
                                <option value="">All actions</option>
                """);

        TreeSet<String> actions =
                new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

        for (AuditLog log : logs) {
            if (log.getAction() != null && !log.getAction().isBlank()) {
                actions.add(log.getAction());
            }
        }

        for (String action : actions) {
            html.append("<option value=\"")
                    .append(escapeHtml(action))
                    .append("\">")
                    .append(escapeHtml(action))
                    .append("</option>");
        }

        html.append("""
                            </select>
                            <select id="resultFilter" aria-label="Filter by result">
                                <option value="">All results</option>
                                <option value="SUCCESS">Success</option>
                                <option value="FAILURE">Failure</option>
                                <option value="DENIED">Denied</option>
                                <option value="BLOCKED">Blocked</option>
                            </select>
                        </div>
                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Role</th>
                                        <th>Action</th>
                                        <th>Target</th>
                                        <th>Details</th>
                                        <th>Result</th>
                                        <th>Timestamp</th>
                                    </tr>
                                </thead>
                                <tbody id="logRows">
                """);

        for (AuditLog log : logs) {
            String username = safe(log.getUsername());
            String action = safe(log.getAction());
            String details = safe(log.getDetails());

            String role = log.getActorRole() == null
                    || log.getActorRole().isBlank()
                            ? "-" : log.getActorRole();

            String target = log.getTarget() == null
                    || log.getTarget().isBlank()
                            ? "-" : log.getTarget();

            String result = safe(log.getResult());

            String timestamp = log.getTimestamp() == null
                    ? "Not available"
                    : log.getTimestamp().format(formatter);

            String resultClass = "SUCCESS".equalsIgnoreCase(result)
                    ? "success"
                    : "FAILURE".equalsIgnoreCase(result)
                            || "DENIED".equalsIgnoreCase(result)
                            || "BLOCKED".equalsIgnoreCase(result)
                            ? "failure" : "neutral";

            html.append("<tr data-username=\"")
                    .append(escapeHtml(username.toLowerCase(Locale.ROOT)))
                    .append("\" data-action=\"")
                    .append(escapeHtml(action.toLowerCase(Locale.ROOT)))
                    .append("\" data-details=\"")
                    .append(escapeHtml(details.toLowerCase(Locale.ROOT)))
                    .append("\" data-result=\"")
                    .append(escapeHtml(result.toUpperCase(Locale.ROOT)))
                    .append("\">");

            html.append("<td>").append(log.getId()).append("</td>");
            html.append("<td>").append(escapeHtml(username)).append("</td>");
            html.append("<td>").append(escapeHtml(role)).append("</td>");
            html.append("<td>").append(escapeHtml(action)).append("</td>");
            html.append("<td>").append(escapeHtml(target)).append("</td>");
            html.append("<td>").append(escapeHtml(details)).append("</td>");
            html.append("<td><span class='pill ")
                    .append(resultClass).append("'>")
                    .append(escapeHtml(result.isBlank() ? "UNKNOWN" : result))
                    .append("</span></td>");
            html.append("<td>").append(escapeHtml(timestamp)).append("</td>");
            html.append("</tr>");
        }

        html.append("""
                                <tr id="noMatches" style="display:none">
                                    <td colspan="8" class="empty">
                                        No records match your search or filters.
                                    </td>
                                </tr>
                """);

        if (logs.isEmpty()) {
            html.append("""
                                <tr>
                                    <td colspan="8" class="empty">
                                        No audit records have been recorded yet.
                                    </td>
                                </tr>
                    """);
        }

        html.append("""
                                </tbody>
                            </table>
                        </div>
                        <div class="footer">
                            <span id="visibleCount"></span>
                            <span>Audit history is read-only on this page.</span>
                        </div>
                    </section>
                </main>
                <script>
                const searchInput = document.getElementById('search');
                const actionFilter = document.getElementById('actionFilter');
                const resultFilter = document.getElementById('resultFilter');
                const rows = Array.from(
                    document.querySelectorAll('#logRows tr[data-username]')
                );
                const noMatches = document.getElementById('noMatches');
                const visibleCount = document.getElementById('visibleCount');

                function filterLogs() {
                    const query = searchInput.value.trim().toLowerCase();
                    const action = actionFilter.value.toLowerCase();
                    const result = resultFilter.value.toUpperCase();
                    let visible = 0;

                    rows.forEach(row => {
                        const textMatches =
                            row.dataset.username.includes(query) ||
                            row.dataset.action.includes(query) ||
                            row.dataset.details.includes(query) ||
                            row.textContent.toLowerCase().includes(query);

                        const actionMatches =
                            !action || row.dataset.action === action;

                        const resultMatches =
                            !result || row.dataset.result === result;

                        const show =
                            textMatches && actionMatches && resultMatches;

                        row.style.display = show ? '' : 'none';

                        if (show) {
                            visible++;
                        }
                    });

                    if (noMatches) {
                        noMatches.style.display =
                            rows.length > 0 && visible === 0 ? '' : 'none';
                    }

                    visibleCount.textContent =
                        'Showing ' + visible + ' of ' + rows.length + ' records';
                }

                searchInput.addEventListener('input', filterLogs);
                actionFilter.addEventListener('change', filterLogs);
                resultFilter.addEventListener('change', filterLogs);
                filterLogs();
                </script>
                </body>
                </html>
                """);

        return html.toString();
    }

    private String safe(String value) {
        return value == null ? "" : value;
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