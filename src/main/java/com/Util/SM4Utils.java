package com.Util;

import com.Pojo.SM4;
import com.Pojo.SM4Context;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SM4Utils {

    public static final Pattern P_MATCH = Pattern.compile("\\s*|\t|\r|\n");

    /**
     * SM4_ECB_PKCS7加密
     * 密文长度不固定，会随着被加密字符串长度的变化而变化
     */
    public static String encryptDatas(String plainText, String secretKey, Boolean isPadding) {
        try {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = isPadding;
            ctx.mode = 1;
            byte[] keyBytes = secretKey.getBytes();
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
            String cipherText = (new BASE64Encoder()).encode(encrypted);
            if (cipherText != null && cipherText.trim().length() > 0) {
                Matcher m = P_MATCH.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            return cipherText;
        } catch (Exception var8) {
            var8.printStackTrace();
            return null;
        }
    }
    /**
     * SM4_ECB_PKCS7解密
     */
    public static String decryptDatas(String cipherText, String secretKey, Boolean isPadding) {
        try {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = isPadding;
            ctx.mode = 0;
            byte[] keyBytes = secretKey.getBytes();
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, (new BASE64Decoder()).decodeBuffer(cipherText));
            return new String(decrypted, "UTF-8");
        } catch (Exception var6) {
            var6.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        // 加解密key
        String secretKey = "";
        // 加解密data
        String data = "";

        System.out.println("1) 传输数据:" + data);
        //加密
        String encrypte = encryptDatas(data, secretKey, true);
        System.out.println("2) 加密后数据:" + encrypte);
        //解密
        String decryptDatas = decryptDatas(encrypte, secretKey, true);
        System.out.println("3) 解密后数据：" + decryptDatas);
    }

}
