package name.stadig.gcm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Unit test for simple App.
 */
public class GCMTest extends TestCase {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public byte[] encryptThenDecrypt(final String transformation, final Key key,
      byte[] data) throws Exception {
    Cipher c = Cipher.getInstance(transformation);
    c.init(Cipher.ENCRYPT_MODE, key);
    final byte[] iv = c.getIV();
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    final CipherOutputStream cos = new CipherOutputStream(baos, c);
    try {
      final byte[] buf = new byte[1024];
      int read = bais.read(buf);
      while (read != -1) {
        cos.write(buf, 0, read);
        read = bais.read(buf);
      }
    } finally {
      cos.close();
    }
    data = baos.toByteArray();
    c = Cipher.getInstance(transformation);
    c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    bais = new ByteArrayInputStream(data);
    final CipherInputStream cis = new CipherInputStream(bais, c);
    baos = new ByteArrayOutputStream();
    try {
      final byte[] buf = new byte[1024];
      int read = cis.read(buf);
      while (read != -1) {
        baos.write(buf, 0, read);
        read = cis.read(buf);
      }
    } finally {
      cis.close();
    }
    return baos.toByteArray();
  }

  public void testRoundtrip() throws Exception {
    final SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    final byte[] keyBytes = new byte[32];
    rand.nextBytes(keyBytes);
    final SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    // this roundtrips fine
    assertEquals(
        "data",
        new String(encryptThenDecrypt("AES/CTR/PKCS5Padding", key,
            "data".getBytes()), "UTF-8"));
    // this gets a NegativeArraySizeException, the only difference being the
    // transformation
    try {
      assertEquals(
          "data",
          new String(encryptThenDecrypt("AES/GCM/NoPadding", key,
              "data".getBytes()), "UTF-8"));
    } catch (final Exception e) {
      fail(e.toString());
    }
  }
}
