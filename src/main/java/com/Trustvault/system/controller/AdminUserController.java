
package com.Trustvault.system.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.repository.Useraccountrepository;
import com.Trustvault.system.service.AuditLogService;

@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

    private final Useraccountrepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DocumentPermissionRepository permissionRepository;
    private final AuditLogService auditLogService;

    public AdminUserController(
            Useraccountrepository userRepository,
            PasswordEncoder passwordEncoder,
            DocumentPermissionRepository permissionRepository,
            AuditLogService auditLogService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.permissionRepository = permissionRepository;
        this.auditLogService = auditLogService;
    }

    private boolean isAdmin(Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getName())) {
            return false;
        }

        Useraccount user = userRepository
                .findByUsername(authentication.getName())
                .orElse(null);

        return user != null
                && "ADMIN".equalsIgnoreCase(user.getRole())
                && user.isEnabled();
    }

    @GetMapping
    @ResponseBody
    public String usersPage(
            Authentication authentication,
            CsrfToken csrf,
            @RequestParam(required = false) String message,
            @RequestParam(required = false) String messageType,
            @RequestParam(required = false, defaultValue = "false") boolean created) {

        if (!isAdmin(authentication)) {
            return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Access Denied</title>
                </head>
                <body>
                    <h2>Access denied</h2>
                    <p>Only active administrators can manage users.</p>
                    <a href="/">Return to Home</a>
                </body>
                </html>
                """;
        }

        String token = escapeHtml(csrf.getToken());
        List<Useraccount> users = userRepository.findAll();
        StringBuilder rows = new StringBuilder();

        for (Useraccount user : users) {

            String username = escapeHtml(user.getUsername());
            String email = user.getEmail() == null
                    || user.getEmail().isBlank()
                            ? "Not provided"
                            : escapeHtml(user.getEmail());

            String role = escapeHtml(user.getRole());
            String status = user.isEnabled() ? "Active" : "Inactive";

            boolean targetIsAdmin =
                    "ADMIN".equalsIgnoreCase(user.getRole());

            boolean isSelf = user.getUsername()
                    .equalsIgnoreCase(authentication.getName());

            rows.append("<tr data-status='")
                    .append(status.toLowerCase(Locale.ROOT))
                    .append("'>")
                    .append("<td class='username-cell'>")
                    .append(username)
                    .append("</td>")
                    .append("<td class='email-cell'>")
                    .append(email)
                    .append("</td>")
                    .append("<td class='role-cell'>")
                    .append(role)
                    .append("</td>")
                    .append("<td class='status-cell'>")
                    .append(status)
                    .append("</td>")
                    .append("<td>");

            if (isSelf) {

                rows.append("<span class='protected'>Current account</span>");

            } else if (targetIsAdmin) {

                rows.append("<span class='protected'>Admin-protected</span>");

            } else {

                String action = user.isEnabled()
                        ? "/admin/users/deactivate"
                        : "/admin/users/activate";

                String buttonText = user.isEnabled()
                        ? "Deactivate"
                        : "Reactivate";

                String buttonClass = user.isEnabled()
                        ? "deactivate"
                        : "activate";

                rows.append("<form method='post' action='")
                        .append(action)
                        .append("' onsubmit=\"return confirm('Confirm this account action?');\">")
                        .append("<input type='hidden' name='_csrf' value='")
                        .append(token)
                        .append("'>")
                        .append("<input type='hidden' name='username' value='")
                        .append(username)
                        .append("'>")
                        .append("<button class='")
                        .append(buttonClass)
                        .append("' type='submit'>")
                        .append(buttonText)
                        .append("</button></form>");
            }

            rows.append("</td></tr>");
        }

        String html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>TrustVault - User Management</title>

                <style>
                    * {
                        box-sizing: border-box;
                    }

                    body {
                        font-family: Arial, sans-serif;
                        background: #f3f5f9;
                        margin: 0;
                        padding: 25px;
                        color: #202b3c;
                    }

                    .container {
                        max-width: 1100px;
                        margin: 20px auto;
                        background: white;
                        padding: 28px;
                        border-radius: 12px;
                        box-shadow: 0 4px 18px #00000012;
                    }

                    h1, h2 {
                        color: #183b70;
                    }

                    label {
                        display: block;
                        margin-top: 15px;
                        font-weight: bold;
                    }

                    input, select {
                        width: 100%;
                        padding: 11px;
                        margin-top: 7px;
                        border: 1px solid #ccd3df;
                        border-radius: 6px;
                        background: white;
                    }

                    button {
                        padding: 10px 14px;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        color: white;
                        margin: 4px 0;
                    }

                    .create {
                        background: #183b70;
                        margin-top: 20px;
                    }

                    .deactivate {
                        background: #b42318;
                    }

                    .activate {
                        background: #18794e;
                    }

                    .filter-panel {
                        margin-top: 20px;
                        padding: 16px;
                        background: #f3f6fb;
                        border: 1px solid #dce4f0;
                        border-radius: 8px;
                        display: grid;
                        grid-template-columns: 2fr 1fr;
                        gap: 16px;
                    }

                    .filter-panel label {
                        margin-top: 0;
                    }

                    .table-wrapper {
                        overflow-x: auto;
                        margin-top: 18px;
                    }

                    table {
                        width: 100%;
                        border-collapse: collapse;
                    }

                    th, td {
                        text-align: left;
                        padding: 12px;
                        border-bottom: 1px solid #e0e5ed;
                    }

                    th {
                        background: #edf2fa;
                    }

                    td form {
                        margin: 0;
                    }

                    a {
                        color: #183b70;
                        margin-right: 15px;
                    }

                    .notice {
                        padding: 12px 14px;
                        border-radius: 6px;
                        margin: 16px 0;
                    }

                    .success {
                        color: #155724;
                        background: #d4edda;
                    }

                    .error {
                        color: #721c24;
                        background: #f8d7da;
                    }

                    .back-button {
                        display: inline-block;
                        background: #183b70;
                        color: white;
                        padding: 11px 18px;
                        border-radius: 6px;
                        text-decoration: none;
                        font-weight: bold;
                        margin-top: 12px;
                    }

                    .back-button:hover {
                        background: #244f8f;
                    }

                    .protected {
                        color: #596579;
                        font-size: 14px;
                    }

                    .result-count {
                        margin-top: 12px;
                        color: #394b63;
                    }

                    @media (max-width: 600px) {
                        body {
                            padding: 10px;
                        }

                        .container {
                            padding: 16px;
                        }

                        th, td {
                            padding: 9px;
                        }

                        .filter-panel {
                            grid-template-columns: 1fr;
                        }
                    }
                </style>
            </head>

            <body>
                <div class="container">
                    <h1>TrustVault</h1>
                    <p>Administrator user management</p>

                    MESSAGE_BOX

                    <h2>Create a Viewer</h2>

                    <form method="post" action="/admin/users">

                        <input type="hidden" name="_csrf"
                               value="CSRF_TOKEN_PLACEHOLDER">

                        <label for="username">Username</label>
                        <input id="username"
                               name="username"
                               required
                               minlength="3"
                               maxlength="40"
                               pattern="[A-Za-z0-9._-]+"
                               autocomplete="off">

                        <label for="email">Email Address</label>
                        <input id="email"
                               name="email"
                               type="email"
                               required
                               maxlength="254"
                               autocomplete="email">

                        <label for="password">Temporary Password</label>
                        <input id="password"
                               name="password"
                               type="password"
                               required
                               minlength="10"
                               maxlength="72"
                               autocomplete="new-password">

                        <input type="hidden" name="role" value="VIEWER">

                        <button class="create" type="submit">
                            Create Viewer
                        </button>
                    </form>

                    <h2 id="existingUsers">Existing Users</h2>

                    <p>
                        Review account roles and status below.
                        Administrator accounts are protected.
                    </p>

                    <div class="filter-panel">
                        <div>
                            <label for="userSearch">Search users</label>
                            <input id="userSearch"
                                   type="search"
                                   placeholder="Search by username, email or role"
                                   autocomplete="off">
                        </div>

                        <div>
                            <label for="statusFilter">Account status</label>
                            <select id="statusFilter">
                                <option value="all">All</option>
                                <option value="active">Active</option>
                                <option value="inactive">Inactive</option>
                            </select>
                        </div>
                    </div>

                    <p id="searchResult" class="result-count" aria-live="polite"></p>

                    <div class="table-wrapper">
                        <table id="usersTable">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="usersTableBody">
                                USER_ROWS_PLACEHOLDER
                            </tbody>
                        </table>
                    </div>

                    <p>
                        <a class="back-button" href="/">Back to Main Page</a>
                    </p>
                </div>

                <script>
                    (function () {
                        const searchInput = document.getElementById("userSearch");
                        const statusFilter = document.getElementById("statusFilter");
                        const searchResult = document.getElementById("searchResult");
                        const tableBody = document.getElementById("usersTableBody");

                        function filterUsers() {
                            const query = searchInput.value.trim().toLowerCase();
                            const selectedStatus = statusFilter.value;
                            const rows = Array.from(tableBody.rows);
                            let visibleCount = 0;

                            rows.forEach(function (row) {
                                const username =
                                    row.cells[0]?.textContent || "";
                                const email =
                                    row.cells[1]?.textContent || "";
                                const role =
                                    row.cells[2]?.textContent || "";
                                const status =
                                    row.cells[3]?.textContent || "";

                                const matchesSearch =
                                    (username + " " + email + " " + role)
                                        .toLowerCase()
                                        .includes(query);

                                const matchesStatus =
                                    selectedStatus === "all"
                                    || status.toLowerCase() === selectedStatus;

                                const visible = matchesSearch && matchesStatus;
                                row.hidden = !visible;

                                if (visible) {
                                    visibleCount++;
                                }
                            });

                            searchResult.textContent =
                                "Showing " + visibleCount + " of "
                                + rows.length + " user(s).";
                        }

                        searchInput.addEventListener("input", filterUsers);
                        statusFilter.addEventListener("change", filterUsers);

                        filterUsers();
                    })();
                </script>
            </body>
            </html>
            """;

        String notice = "";

        if (message != null && !message.isBlank()) {

            String cssClass =
                    "success".equalsIgnoreCase(messageType)
                            ? "success"
                            : "error";

            notice = "<div class='notice " + cssClass
                    + "' role='status'>"
                    + escapeHtml(message)
                    + "</div>";
        }

        return html.replace("MESSAGE_BOX", notice)
                .replace("CSRF_TOKEN_PLACEHOLDER", token)
                .replace("USER_ROWS_PLACEHOLDER", rows.toString());
    }

    @PostMapping
    public String createUser(
            Authentication authentication,
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam(required = false, defaultValue = "VIEWER") String role) {

        if (!isAdmin(authentication)) {
            return redirectWithMessage(
                    "Only active administrators can create users.", "error");
        }

        username = username.trim();

        final String normalizedEmail =
                email.trim().toLowerCase(Locale.ROOT);

        // Validate username
        if (!username.matches("[A-Za-z0-9._-]{3,40}")) {
            return redirectWithMessage(
                    "Invalid username. Use 3-40 letters, numbers, dots, underscores or hyphens.",
                    "error");
        }

        // Validate email
        if (normalizedEmail.isEmpty()
                || normalizedEmail.length() > 254
                || !normalizedEmail.matches(
                "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {

            return redirectWithMessage(
                    "Please enter a valid email address.", "error");
        }

        // Validate password
        if (password.length() < 10
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {

            return redirectWithMessage(
                    "Use a password of at least 10 characters and no more than 72 UTF-8 bytes.",
                    "error");
        }

        // Admin can create Viewer accounts only
        if (!"VIEWER".equalsIgnoreCase(role)) {

            auditLogService.log(
                    authentication.getName(),
                    "USER_CREATE_BLOCKED",
                    "Admin attempted to create a non-Viewer account",
                    "BLOCKED");

            return redirectWithMessage(
                    "Administrators can create Viewer accounts only. Owners must register themselves.",
                    "error");
        }

        // Check duplicate username
        final String requestedUsername = username;

        boolean usernameExists = userRepository.findAll().stream()
                .anyMatch(existing -> requestedUsername
                        .equalsIgnoreCase(existing.getUsername()));

        if (usernameExists) {
            return redirectWithMessage(
                    "That username already exists. Choose another.", "error");
        }

        // Check duplicate email
        boolean emailExists = userRepository.findAll().stream()
                .anyMatch(existing ->
                        existing.getEmail() != null
                        && normalizedEmail.equalsIgnoreCase(
                                existing.getEmail().trim()));

        if (emailExists) {
            return redirectWithMessage(
                    "That email address is already registered. Use another email.",
                    "error");
        }

        // Create Viewer account
        Useraccount newUser = new Useraccount();

        newUser.setUsername(username);
        newUser.setEmail(normalizedEmail);
        newUser.setPasswordHash(passwordEncoder.encode(password));
        newUser.setRole("VIEWER");
        newUser.setEnabled(true);

        try {
            userRepository.save(newUser);
        } catch (DataIntegrityViolationException exception) {

            return redirectWithMessage(
                    "Username or email is already registered. Please check the details.",
                    "error");
        }

        // Record successful creation
        auditLogService.log(
                authentication.getName(),
                "USER_CREATED",
                username,
                "Created Viewer account",
                "SUCCESS");

        return redirectWithMessage(
                "Viewer account \"" + username + "\" created successfully.",
                "success");
    }

    @PostMapping("/deactivate")
    @Transactional
    public String deactivateUser(
            Authentication authentication,
            @RequestParam String username) {

        if (!isAdmin(authentication)) {
            return redirectWithMessage(
                    "Only active administrators can deactivate accounts.", "error");
        }

        Useraccount target = userRepository
                .findByUsername(username.trim())
                .orElse(null);

        if (target == null) {
            return redirectWithMessage(
                    "The requested account does not exist.", "error");
        }

        if ("ADMIN".equalsIgnoreCase(target.getRole())) {

            auditLogService.log(
                    authentication.getName(),
                    "USER_DEACTIVATION_BLOCKED",
                    "Attempted to deactivate an administrator account",
                    "BLOCKED");

            return redirectWithMessage(
                    "Administrator accounts cannot be deactivated from this page.",
                    "error");
        }

        if (!target.isEnabled()) {
            return redirectWithMessage(
                    "This account is already inactive.", "error");
        }

        target.setEnabled(false);
        userRepository.save(target);

        permissionRepository.deleteByViewerUsername(target.getUsername());

        auditLogService.log(
                authentication.getName(),
                "USER_DEACTIVATED",
                target.getUsername(),
                "Deactivated account",
                "SUCCESS");

        return redirectWithMessage(
                "Account \"" + target.getUsername()
                        + "\" deactivated. Sharing permissions were revoked; "
                        + "existing documents were preserved.",
                "success");
    }

    @PostMapping("/activate")
    public String activateUser(
            Authentication authentication,
            @RequestParam String username) {

        if (!isAdmin(authentication)) {
            return redirectWithMessage(
                    "Only active administrators can reactivate accounts.", "error");
        }

        Useraccount target = userRepository
                .findByUsername(username.trim())
                .orElse(null);

        if (target == null) {
            return redirectWithMessage(
                    "The requested account does not exist.", "error");
        }

        if ("ADMIN".equalsIgnoreCase(target.getRole())) {

            auditLogService.log(
                    authentication.getName(),
                    "USER_REACTIVATION_BLOCKED",
                    "Attempted to reactivate an administrator account",
                    "BLOCKED");

            return redirectWithMessage(
                    "Administrator accounts cannot be managed from this page.",
                    "error");
        }

        if (target.isEnabled()) {
            return redirectWithMessage(
                    "This account is already active.", "error");
        }

        target.setEnabled(true);
        userRepository.save(target);

        auditLogService.log(
                authentication.getName(),
                "USER_REACTIVATED",
                target.getUsername(),
                "Reactivated account",
                "SUCCESS");

        return redirectWithMessage(
                "Account \"" + target.getUsername()
                        + "\" reactivated. Previous sharing permissions "
                        + "were not restored automatically.",
                "success");
    }

    private String redirectWithMessage(String message, String type) {

        return "redirect:/admin/users?message="
                + URLEncoder.encode(message, StandardCharsets.UTF_8)
                + "&messageType="
                + URLEncoder.encode(type, StandardCharsets.UTF_8);
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
