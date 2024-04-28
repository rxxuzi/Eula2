package eula;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <h1>EulaHash</h1>
 * Provides utility functions for cryptographic hash operations and random string generation for use in key derivation.
 * <p>
 * This class encapsulates methods for generating secure random strings, which are essential for creating strong keys.
 * It also offers functions to compute hashes using robust algorithms, suitable for ensuring data integrity and supporting authentication mechanisms.
 * </p>
 * <p>
 * The main features include generating random strings that can be used directly as keys or salts in cryptographic operations,
 * and computing hashes from given strings using secure hashing algorithms, which are critical for password storage and verification.
 * </p>
 *
 * @author rxxuzi
 */
public class EulaHash {

    private final String hash_256;
    private final String hash_512;

    public EulaHash(String text) throws EulaException {
        this.hash_256 = sha256(text);
        this.hash_512 = sha512(text);
    }

    public EulaHash(File file) throws EulaException {
        this.hash_256 = sha256(file);
        this.hash_512 = sha512(file);
    }

    public EulaHash(Object obj) throws EulaException {
        this.hash_256 = sha256(obj);
        this.hash_512 = sha512(obj);
    }

    // ランダムな文字列を生成する。(64文字)
    public static String randomString() {
        int max = 64;
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < max; i++) {
            sb.append((char) (random.nextInt(79) + '0'));
        }
        return sb.toString();
    }

    private static String hash(String Algorithm, byte[] data) throws EulaException {
        try {
            MessageDigest digest = MessageDigest.getInstance(Algorithm);
            return bytesToHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new EulaException("Algorithm not found in hash", e);
        }
    }

    public static String sha256(String str) throws EulaException {
        return hash("SHA-256", str.getBytes());
    }

    public static String sha256(File file) throws EulaException {
        try {
            byte[] data = Files.readAllBytes(file.toPath());
            return hash("SHA-256", data);
        } catch (IOException e) {
            throw new EulaException("File read error", e);
        }
    }

    public static String sha256(Object obj) throws EulaException {
        try {
            return hash("SHA-256", serialize(obj));
        } catch (IOException e) {
            throw new EulaException("Serialize error", e);
        }
    }

    public static String sha512(String str) throws EulaException {
        return hash("SHA-512", str.getBytes());
    }

    public static String sha512(File file) throws EulaException {
        try {
            byte[] data = Files.readAllBytes(file.toPath());
            return hash("SHA-512", data);
        } catch (IOException e) {
            throw new EulaException("File read error", e);
        }
    }

    public static String sha512(Object obj) throws EulaException {
        try {
            return hash("SHA-512", serialize(obj));
        } catch (IOException e) {
            throw new EulaException("Serialize error", e);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
        return baos.toByteArray();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof EulaHash other) {
            return this.hash_256.equals(other.hash_256) && this.hash_512.equals(other.hash_512);
        }
        return false;
    }

    @Override
    public String toString() {
        return "SHA-256 : " + hash_256 + "\nSHA-512 : " + hash_512;
    }
}
