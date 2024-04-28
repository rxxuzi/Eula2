package eula;

import net.jpountz.lz4.LZ4BlockInputStream;
import net.jpountz.lz4.LZ4BlockOutputStream;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * <h1>EulaFast</h1>
 * Provides optimized methods for encrypting and decrypting files quickly.
 * <p>
 * This class is a component of the Eula project, designed to facilitate file encryption with an emphasis on performance and simplicity.
 * It is particularly suitable for handling large files or for use in high-throughput environments.
 * </p>
 * <p>
 * EulaFast was inspired by the predecessor project, Eula, which can be found at the following link:
 * <a href="https://github.com/rxxuzi/Eula">Eula on GitHub</a>.
 * </p>
 * <h2>Usage:</h2>
 * <ul>
 *     <li>
 *         <b>Encryption:</b> Encrypts the file using a specified secret key and optionally deletes the original file.
 *         {@snippet lang="java" :
 *         SecretKey secretKey; // Obtain your AES key;
 *         File inputFile = new File("path/to/input.file");
 *         boolean deleteOriginal = true;
 *         EulaFast.encrypt(secretKey, inputFile, deleteOriginal);
 *         }
 *     </li>
 *     <li>
 *         <b>Decryption:</b> Decrypts the file using the specified secret key and optionally deletes the encrypted file.
 *         {@snippet lang="java" :
 *         SecretKey secretKey ; // Obtain your AES key;
 *         File encryptedFile = new File("path/to/encrypted.file");
 *         boolean deleteEncrypted = true;
 *         EulaFast.decrypt(secretKey, encryptedFile, deleteEncrypted);
 *         }
 *     </li>
 * </ul>
 *
 * @see <a href="https://github.com/rxxuzi/Eula">Eula on GitHub</a>
 * @author rxxuzi
 */

public class EulaFast {
    private static final int BUFFER_SIZE = 8192;
    private static final String EXTENSION = ".eula";

    // 暗号化メソッド
    public static void encrypt(SecretKey key, File inputFile, boolean delete) throws EulaException {
        ByteArrayOutputStream compressedOutputStream = new ByteArrayOutputStream();

        try (FileInputStream fis = new FileInputStream(inputFile);
             LZ4BlockOutputStream lz4OutputStream = new LZ4BlockOutputStream(compressedOutputStream);
             CipherOutputStream cos = new CipherOutputStream(lz4OutputStream, getCipher(Cipher.ENCRYPT_MODE, key))) {

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new EulaException("Error reading file", e);
        }

        try (FileOutputStream fos = new FileOutputStream(inputFile.getAbsolutePath() + EXTENSION)) {
            fos.write(compressedOutputStream.toByteArray());
        } catch (IOException e){
            throw new EulaException("Error writing encrypted file", e);
        }

        if (delete) inputFile.delete();
    }

    // 復号化メソッド
    public static void decrypt(SecretKey key, File inputFile, boolean delete) throws EulaException{
        if (inputFile.getPath().endsWith(EXTENSION)) {
            try (FileInputStream fis = new FileInputStream(inputFile);
                 LZ4BlockInputStream lz4InputStream = new LZ4BlockInputStream(fis);
                 CipherInputStream cis = new CipherInputStream(lz4InputStream, getCipher(Cipher.DECRYPT_MODE, key));
                 FileOutputStream fos = new FileOutputStream(EulaAES.removeExtension(inputFile.getAbsolutePath()))) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                throw new EulaException("Error reading encrypted file", e);
            }

            if (delete) inputFile.delete();
        }
    }

    // Cipherオブジェクトを取得するユーティリティメソッド
    private static Cipher getCipher(int cipherMode, SecretKey secretKey) throws EulaException {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, secretKey);
            return cipher;
        } catch (NoSuchPaddingException e) {
            throw new EulaException("Padding problem in encryption/decryption", e);
        } catch (NoSuchAlgorithmException e) {
            throw new EulaException("Algorithm not found in encryption/decryption", e);
        } catch (InvalidKeyException e) {
            throw new EulaException("Invalid key in encryption/decryption", e);
        }
    }
}
