package eula;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * <h1>Eula</h1>
 * Provides a comprehensive encryption solution utilizing AES and RSA algorithms for secure file encryption and key exchange.
 * <p>
 * This class facilitates two primary modes of operation, selectable based on the constructor used:
 * <ul>
 *     <li><b>Asymmetric Key Encryption:</b> Default constructor initializes RSA for secure key exchange and AES for file encryption.</li>
 *     <li><b>Symmetric Key Encryption:</b> Constructor with a password parameter utilizes AES encryption exclusively with a predetermined secret key.</li>
 * </ul>
 * It abstracts the complexities involved in file encryption and decryption processes to ensure robust security.
 * By leveraging AES for fast and secure file encryption and RSA for secure key exchange, this class offers an efficient interface for encrypting files for secure storage or transmission and for decrypting them upon retrieval.
 * </p>
 *
 * <p>
 *     <b>Usage Example (RSA - Asymmetric Key):</b>
 * {@snippet lang="java" :
 *     // Initialize a file for encryption
 *     File file = new File("sample.txt");
 *     Eula encryptor = new Eula();
 *     Eula decryptor = new Eula();
 *
 *     // Generate and distribute public key
 *     String publicKey = decryptor.share();
 *     encryptor.encrypt(file, false);  // Encrypts the file; resulting in "sample.txt.eula"
 *     String encryptedKey = encryptor.openKey(publicKey);  // Encrypts AES key using public key for sharing
 *
 *     // Decrypt the encrypted file using the shared encrypted key
 *     File encryptedFile = new File("sample.txt.eula");
 *     decryptor.decrypt(encryptedKey, encryptedFile, false);
 * }
 * </p>
 *
 * <p>
 *     <b>Usage Example (AES - Symmetric Key):</b>
 *     {@snippet lang="java" :
 *     // Utilize a predefined password for encryption
 *     String password = "password123";
 *     File file = new File("sample.txt");
 *     Eula encryptor = new Eula(password);
 *     Eula decryptor = new Eula(password);
 *
 *     // Perform encryption and decryption of the file
 *     encryptor.encrypt(file, false);
 *     File encryptedFile = new File("sample.txt.eula");
 *     decryptor.decrypt(encryptedFile, false);
 *     }
 * </p>
 *
 * <h2>Note</h2>
 * Effective management of cryptographic keys and sensitive file data is imperative to maintain security.
 * Negligence or incorrect usage can result in significant security breaches.
 *
 * @author rxxuzi
 * @see EulaRSA
 * @see EulaAES
 */

public class Eula implements Serializable{
    // rsaとaes
    private transient final EulaRSA rsa;
    private transient final EulaAES aes;

    // 暗号化に使う鍵
    private final transient SecretKey key;

    // 公開鍵と秘密鍵
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    private final String password;

    // コンストラクタ。パスワードはランダム生成
    public Eula() throws EulaException {
        this.password = EulaHash.randomString();
        this.rsa = new EulaRSA();
        this.aes = new EulaAES(password);
        this.key = aes.key;
        this.publicKey = rsa.publicKey;
        this.privateKey = rsa.privateKey;
    }

    public Eula(String password) throws EulaException {
        this.password = password;
        this.rsa = new EulaRSA();
        this.aes = new EulaAES(password);
        this.key = aes.key;
        this.publicKey = rsa.publicKey;
        this.privateKey = rsa.privateKey;
    }

    public void encrypt(SecretKey key, File file, boolean del) throws EulaException {
        EulaFast.encrypt(key, file, del);
    }

    public void encrypt(File file, boolean del) throws EulaException {
        EulaFast.encrypt(this.key, file, del);
    }

    public void encrypt(List<File> files, boolean del) throws EulaException {
        files.parallelStream().forEach(file -> {
                    try {
                        EulaFast.encrypt(this.key, file, del);
                    } catch (EulaException e) {
                        e.printStackTrace();
                    }
                }
        );
    }

    public void decrypt(SecretKey key, File file, boolean del) throws EulaException {
        EulaFast.decrypt(key, file, del);
    }

    public void decrypt(File file, boolean del) throws EulaException {
        EulaFast.decrypt(this.key, file, del);
    }

    public void decrypt(String encryptedKey, File file, boolean del) throws EulaException {
        EulaFast.decrypt(this.closeKey(encryptedKey), file, del);
    }

    public void decrypt(List<File> files, boolean del) throws EulaException {
        files.parallelStream().forEach(file -> {
                    try {
                        EulaFast.encrypt(this.key, file, del);
                    } catch (EulaException e) {
                        e.printStackTrace();
                    }
                }
        );
    }

    // 公開鍵を共有する
    public String share() {
        return rsa.getPublicKeyString(); // 公開鍵を文字列で返す
    }

    // 公開鍵でキーを暗号化し、文字列を返す.
    // 公開鍵は文字列で与えられる
    public String openKey(String pubkey) throws EulaException {
        // 引数から公開鍵を取得
        PublicKey publicKey = rsa.toPublicKey(pubkey);
        try {
            byte[] encryptedKey = EulaRSA.encAES(this.key, publicKey);
            return Base64.getEncoder().encodeToString(encryptedKey); // Base64エンコードされた文字列を返す
        } catch (Exception e) {
            throw new EulaException("Failed to encrypt AES key with public key.", e);
        }
    }

    // 秘密鍵でキーを復号化し、SecretKeyを返す.
    // 秘密鍵は自分の秘密鍵を使う
    public SecretKey closeKey(String base64) throws EulaException {
        try {
            // Base64でエンコードされた文字列をデコードしてバイト配列に変換
            byte[] encryptedKey = Base64.getDecoder().decode(base64);
            // 秘密鍵を使用してAES鍵を復号化
            return EulaRSA.decAES(encryptedKey, this.privateKey);
        } catch (Exception e) {
            throw new EulaException("Failed to decrypt AES key with private key.", e);
        }
    }


    @Override
    public String toString() {
        String sha256;
        try {
            sha256 = EulaHash.sha256(this);
        } catch (EulaException e) {
            sha256 = "Error";
        }

        String header    = "EULA     : \n";
        String footer    = "\n";
        String password  = "PASSWORD : " + this.password + "\n";
        String hash      = "HASH     : " + sha256 + "\n";
        String publicKey = "PUBLIC KEY    : " + this.publicKey.toString() + "\n";
        String privateKey= "PRIVATE KEY   : " + this.privateKey.toString() + "\n";

        return header + password + hash + publicKey + privateKey + footer;
    }
}
