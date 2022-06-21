package cn.learndevops.filecrypto;

import javafx.concurrent.Task;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class FileProcessor extends Task<Boolean> {
    public static final int BLOCK_SIZE = 1024 * 1024;
    private final Cipher cipher;
    private File inputFile;
    private File outputFile;

    public FileProcessor(byte[] keyBytes, byte[] ivBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    }

    public void setFile(File inputFile, File outputFile) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
    }

    @Override
    protected Boolean call() throws Exception {
        System.out.println("Task started.");
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(inputFile));
        BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(outputFile));
        var file_size = inputFile.length();
        System.out.printf("file size: %d\n", file_size);
        long file_processed = 0;
        byte[] block = new byte[BLOCK_SIZE];
        int n_read;
        while (true) {
            n_read = reader.read(block);
            if (n_read <= 0) {
                break;
            }
            byte[] output = cipher.update(block);
            //System.out.printf("n_read: %d\n",n_read);
            writer.write(output, 0, n_read);
            file_processed += n_read;
            updateProgress(file_processed, file_size);
            //System.out.println((double) file_processed / file_size);
        }
        reader.close();
        writer.close();
        System.out.print("finished\n");
        return true;
    }
}
