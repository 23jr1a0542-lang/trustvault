package com.Trustvault.system.document;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class DocumentStorageService {

    private final Path storageDirectory;

    public DocumentStorageService(
            @Value("${trustvault.storage-dir:trustvault-files}")
            String storageDirectory) throws IOException {

        this.storageDirectory = Paths.get(storageDirectory)
                .toAbsolutePath()
                .normalize();

        Files.createDirectories(this.storageDirectory);
    }

    public String store(MultipartFile file) throws IOException {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please select a file.");
        }

        String originalName = file.getOriginalFilename();

        if (originalName == null || originalName.isBlank()) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        // Do not trust a filename containing directory paths.
        String safeName = Paths.get(originalName)
                .getFileName()
                .toString();

        if (safeName.isBlank() || safeName.contains("..")) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        // Store using a random server-side name.
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

        // Enforce boundary check to prevent path traversal
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

            // Enforce boundary check
            if (!destination.startsWith(storageDirectory)) {
                throw new SecurityException("Access to path outside storage directory is forbidden.");
            }

            return Files.deleteIfExists(destination);
        } catch (Exception e) {
            System.err.println("Failed to delete file from storage disk: " + e.getMessage());
            return false;
        }
    }
}
