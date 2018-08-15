package com.naughtyzombie.jwtreg;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.*;

@CommandLine.Command(name = "jwtreg", mixinStandardHelpOptions = true, version = "JWT Registration App")
public class JWTReg implements Runnable {

    @Option(names = {"-i","--software-statement-id"}, arity = "1", description = "Software Statement Id")
    private String ssId;

    @Option(names = {"-s", "--software-statement"}, arity = "1", description = "Software Statement")
    private File softwareStatementFile;

    @Option(names = {"-p", "--private-key"}, arity = "1", description = "Private RSA Key")
    private File privateKeyFile;

    @Option(names = {"-k","--key-id"}, arity = "1", description = "Key Id")
    private String kid;


    public void run() {
        try {
            String ssa = new String(Files.readAllBytes(softwareStatementFile.toPath()));
            System.out.println(ssa);

            String privateKey = new String(Files.readAllBytes(privateKeyFile.toPath()));
            System.out.println(privateKey);

            List<String> grantTypes = Arrays.asList("authorization_code", "refresh_token", "client_credentials");
            List<String> redirectUris = Collections.singletonList("https://app.getpostman.com/oauth2/callback");
            List<String> responseTypes = Arrays.asList("code", "code id_token");

            LocalDate now = LocalDate.now();
            LocalDate exp = now.plusDays(3650);

            Map<String, Object> claims = new HashMap<>();
            claims.put("token_endpoint_auth_signing_alg","RS256");
            claims.put("request_object_encryption_alg","RSA-OAEP-256");
            claims.put("grant_types", grantTypes);
            claims.put("subject_type","public");
            claims.put("application_type","web");
            claims.put("iss",ssId);
            claims.put("redirect_uris", redirectUris);
            claims.put("token_endpoint_auth_method","private_key_jwt");
            claims.put("aud","https://as.aspsp.ob.forgerock.financial/oauth2/openbanking");
            claims.put("scope","openid accounts");
            claims.put("request_object_signing_alg","RS256");
            claims.put("exp",exp);
            claims.put("iat",now);
            claims.put("request_object_encryption_enc","A128CBC-HS256");
            claims.put("jti", UUID.randomUUID());
            claims.put("response_types", responseTypes);
            claims.put("id_token_signed_response_alg","ES256");
            claims.put("software_statement",ssa);

            RSAPrivateKey privateKeyFromString = getPrivateKeyFromString(privateKey);

            Map<String, Object> headerParams = new HashMap<>();
            headerParams.put("alg","RS256");
            headerParams.put("kid",kid);
            headerParams.put("typ","JWT");

            System.out.println(Jwts.builder().setHeaderParams(headerParams).addClaims(claims).signWith(privateKeyFromString).toString());



        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {
        CommandLine.run(new JWTReg(), System.out, args);
    }

    private String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }
    public RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    public RSAPrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }


    public RSAPublicKey getPublicKey(String filename) throws IOException, GeneralSecurityException {
        String publicKeyPEM = getKey(filename);
        return getPublicKeyFromString(publicKeyPEM);
    }

    public RSAPublicKey getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
        return pubKey;
    }

    public String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initSign(privateKey);
        sign.update(message.getBytes("UTF-8"));
        return new String(Base64.getDecoder().decode(sign.sign()), "UTF-8");
    }


    public boolean verify(PublicKey publicKey, String message, String signature) throws SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initVerify(publicKey);
        sign.update(message.getBytes("UTF-8"));
        return sign.verify(Base64.getDecoder().decode(signature.getBytes("UTF-8")));
    }

//    public String encrypt(String rawText, PublicKey publicKey) throws IOException, GeneralSecurityException {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return Base64.getEncoder().encode (rawText.getBytes("UTF-8"));
//    }

    public String decrypt(String cipherText, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)), "UTF-8");
    }
}
