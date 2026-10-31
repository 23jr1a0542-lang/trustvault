package com.Trustvault.system.document;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class DocumentStorageService {

    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "txt", "csv", "rtf", "png", "jpg", "jpeg", "gif", "bmp"
    );

    private final Path storageDirectory;

    public DocumentStorageService(
            @Value("${trustvault.storage-dir:trustvault-files}")
            String storageDirectory) throws IOException {

        this.storageDirectory = Paths.get(storageDirectory)
                .toAbsolutePath()
                .normalize();

        Files.createDirectories(this.storageDirectory);
    }

    public void validateUpload(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please select a file.");
        }

        String originalName = file.getOriginalFilename();
        if (originalName == null || originalName.isBlank()) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        String safeName = Paths.get(originalName.replace('\\', '/'))
                .getFileName()
                .toString();

        if (safeName.isBlank() || safeName.contains("..")) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        String extension = getExtension(safeName);
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException(
                    "Unsupported file type. Allowed types: PDF, Word, Excel, PowerPoint, text, and common image formats.");
        }

        byte[] content = file.getBytes();
        if (content.length == 0) {
            throw new IllegalArgumentException("The selected file is empty.");
        }

        if (!matchesMagicBytes(content, extension)) {
            throw new IllegalArgumentException("The file content does not match the selected file type.");
        }
    }

    public String store(MultipartFile file) throws IOException {
        validateUpload(file);

        String originalName = file.getOriginalFilename();
        String safeName = Paths.get(originalName.replace('\\', '/'))
                .getFileName()
                .toString();

        String storedName = UUID.randomUUID().toString();
        Path destination = storageDirectory.resolve(storedName).normalize();

        if (!destination.startsWith(storageDirectory)) {
            throw new IllegalArgumentException("Invalid storage path.");
        }

        try (InputStream input = file.getInputStream()) {
            Files.copy(input, destination, StandardCopyOption.REPLACE_EXISTING);
        }

        return destination.toString();
    }

    public Resource loadAsResource(String storagePath) throws IOException {
        if (storagePath == null || storagePath.isBlank()) {
            throw new FileNotFoundException("Document storage path is missing.");
        }

        Path destination = Paths.get(storagePath).toAbsolutePath().normalize();

        if (!destination.startsWith(storageDirectory)) {
            throw new SecurityException("Access to path outside storage directory is forbidden.");
        }

        if (!Files.exists(destination) || !Files.isReadable(destination) || Files.isDirectory(destination)) {
            throw new FileNotFoundException("File not found on storage disk.");
        }

        try {
            Resource resource = new UrlResource(destination.toUri());
            if (resource.exists() && resource.isReadable()) {
                return resource;
            } else {
                throw new FileNotFoundException("Unable to read file: " + destination.getFileName());
            }
        } catch (MalformedURLException e) {
            throw new FileNotFoundException("Malformed storage URL: " + e.getMessage());
        }
    }

    public boolean deleteFile(String storagePath) {
        if (storagePath == null || storagePath.isBlank()) {
            return false;
        }

        try {
            Path destination = Paths.get(storagePath).toAbsolutePath().normalize();

            if (!destination.startsWith(storageDirectory)) {
                throw new SecurityException("Access to path outside storage directory is forbidden.");
            }

            return Files.deleteIfExists(destination);
        } catch (Exception e) {
            System.err.println("Failed to delete file from storage disk: " + e.getMessage());
            return false;
        }
    }

    private String getExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot < 0 || lastDot == fileName.length() - 1) {
            return "";
        }
        return fileName.substring(lastDot + 1).toLowerCase(Locale.ROOT);
    }

    private boolean matchesMagicBytes(byte[] content, String extension) {
        if (content == null || content.length < 4) {
            return false;
        }

        switch (extension) {
            case "pdf":
                return content.length >= 4
                        && content[0] == 0x25 && content[1] == 0x50
                        && content[2] == 0x44 && content[3] == 0x46;
            case "png":
                return content.length >= 8
                        && content[0] == (byte) 0x89 && content[1] == 0x50
                        && content[2] == 0x4E && content[3] == 0x47
                        && content[4] == 0x0D && content[5] == 0x0A
                        && content[6] == 0x1A && content[7] == 0x0A;
            case "jpg":
            case "jpeg":
                return content.length >= 3
                        && (content[0] & 0xFF) == 0xFF
                        && (content[1] & 0xFF) == 0xD8
                        && (content[2] & 0xFF) == 0xFF;
            case "gif":
                return content.length >= 6
                        && ((content[0] == 'G' && content[1] == 'I' && content[2] == 'F')
                        || (content[0] == 0x47 && content[1] == 0x49 && content[2] == 0x46));
            case "bmp":
                return content.length >= 2
                        && content[0] == 0x42 && content[1] == 0x4D;
            case "doc":
            case "xls":
            case "ppt":
                return content.length >= 8
                        && content[0] == (byte) 0xD0 && content[1] == (byte) 0xCF
                        && content[2] == 0x11 && content[3] == (byte) 0xE0
                        && content[4] == (byte) 0xA1 && content[5] == (byte) 0xB1
                        && content[6] == 0x1A && content[7] == (byte) 0xE1;
            case "docx":
            case "xlsx":
            case "pptx":
                return content.length >= 4
                        && content[0] == 'P' && content[1] == 'K';
            case "txt":
            case "csv":
            case "rtf":
                return true;
            default:
                return false;
        }
    }
}
