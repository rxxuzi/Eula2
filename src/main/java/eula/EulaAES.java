package eula;


import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * <h1>EulaAES</h1>
 * Provides robust AES encryption and decryption functionalities.
 * <p>
 * This class is designed to handle the generation, management, and usage of AES keys for secure file encryption.
 * It allows for AES keys to be generated either from a user-specified password or randomly. The class also facilitates
 * the conversion of AES keys to and from Base64-encoded strings, allowing for easy storage and transmission.
 * </p>
 * <p>
 * Key features include:
 * <ul>
 *     <li>Generating AES keys using a password with PBKDF2WithHmacSHA256, ensuring strong key derivation.</li>
 *     <li>Creating random strings suitable for secure key generation.</li>
 *     <li>Utility methods for managing file names and extensions associated with encrypted files, such as adding or removing specific extensions.</li>
 * </ul>
 * These capabilities make EulaAES ideal for applications that require high levels of data security.
 * </p>
 *
 * @author rxxuzi
 */
public final class EulaAES {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    private static final int ITERATION_COUNT = 65536;

    private static final byte[] SALT = "Eula Lawrence".getBytes();
    private static final String EXTENSION = ".eula";

    public final SecretKey key;
    public final boolean pw;

    public EulaAES(String password) throws EulaException {
        this.key = genKey(password);
        this.pw = true;
    }

    // 文字列からAES鍵を取得
    public static SecretKey string2Key(String aesString) {
        return new SecretKeySpec(Base64.getDecoder().decode(aesString), ALGORITHM); // AES鍵を取得
    }

    // AES 鍵をBase64エンコードされた文字列として取得
    public static String key2string(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // 特定の文字列からキーを生成する
    private static SecretKey genKey(String password) throws EulaException {
        try {
            return getKeyFromPassword(password);
        } catch (NoSuchAlgorithmException e) {
            throw new EulaException("No such algorithm for key generation", e);
        } catch (InvalidKeySpecException e) {
            throw new EulaException("Invalid key specification for key generation", e);
        }
    }

    // ファイルの拡張子を削除する。
    public static String removeExtension(String path) {
        if (path.endsWith(EXTENSION)) {
            return path.substring(0, path.length() - EXTENSION.length());
        }
        return path;
    }

    // パスワードからキーを生成する。
    private static SecretKey getKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT, KEY_SIZE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
    }

}