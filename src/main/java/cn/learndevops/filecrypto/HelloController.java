package cn.learndevops.filecrypto;

import javafx.event.ActionEvent;
import javafx.scene.control.*;
import javafx.scene.input.DragEvent;
import javafx.scene.input.TransferMode;
import javafx.stage.FileChooser;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.util.Arrays;

public class HelloController {
    public Label fileNameLabel;
    public Button buttonEncrypt;
    public ProgressBar progressBar;
    public Button buttonDecrypt;
    private File sourceFile;

    public void onDragDropped(DragEvent dragEvent) {
        var db = dragEvent.getDragboard();
        var success = false;
        if (db.hasFiles()) {
            sourceFile = db.getFiles().get(0);
            fileNameLabel.setText(sourceFile.toString());
            success = true;
        }
        dragEvent.setDropCompleted(success);
        dragEvent.consume();
    }

    public void onDragOver(DragEvent dragEvent) {
        if (dragEvent.getDragboard().hasFiles()) {
            dragEvent.acceptTransferModes(TransferMode.COPY);
        }
        dragEvent.consume();

    }

    public void onEncryptButtonClick(ActionEvent actionEvent) {
        if (sourceFile == null) {
            sourceFile = chooseFile();
            if (sourceFile != null) {
                fileNameLabel.setText(String.format("Encrypt: %s", sourceFile.getName()));
                System.out.printf("Encrypt: %s\n", sourceFile);
            } else {
                System.out.println("No file selected.");
                return;
            }
        }

        byte[] keyBytes;
        byte[] ivBytes;

        var passwordDialog = new PasswordDialog();
        var result = passwordDialog.showAndWait();
        if (result.isPresent()) {
            System.out.printf("password: %s\n", result.get());
            try {
                var kdf_data = CryptoUtil.kdf_scrypt(result.get().toCharArray());
                System.out.printf("kdf: %s\n", Hex.toHexString(kdf_data));
                keyBytes = Arrays.copyOfRange(kdf_data, 0, 16);
                ivBytes = Arrays.copyOfRange(kdf_data, 16, 32);
                System.out.printf("key: %s\n", Hex.toHexString(keyBytes));
                System.out.printf("iv : %s\n", Hex.toHexString(ivBytes));

            } catch (Exception e) {
                System.out.println(e.getMessage());
                return;
            }

        } else {
            return;
        }

        var destFilename = String.format("%s.%s.enc",
                sourceFile.getName(),
                Hex.toHexString(Arrays.copyOfRange(ivBytes, 0, 4)));
        System.out.printf("dest filename: %s\n", destFilename);

        var saveFile = saveFile(destFilename);
        if (saveFile != null) {
            fileNameLabel.setText(String.format("Encrypt: %s", saveFile));
            System.out.printf("Encrypt to save: %s\n", saveFile);
        } else {
            System.out.println("No file selected.");
            return;
        }

        try {
            var processor = new FileProcessor(keyBytes, ivBytes);
            processor.setFile(sourceFile, saveFile);
            processor.setOnSucceeded(wse -> {
                System.out.println("worker done.");
                sourceFile = null;
                fileNameLabel.setText("worker done.");
                progressBar.progressProperty().unbind();
                progressBar.setProgress(0);
            });
            processor.setOnFailed(wse -> wse.getSource().getException().printStackTrace());
            progressBar.progressProperty().unbind();
            progressBar.progressProperty().bind(processor.progressProperty());
            var worker = new Thread(processor);
            Thread.UncaughtExceptionHandler handler = (t, e) -> System.out.println(e.getMessage());
            worker.setUncaughtExceptionHandler(handler);
            worker.setDaemon(true);
            worker.start();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private File saveFile(String destFilename) {
        var fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(sourceFile.getParent()));
        fileChooser.setInitialFileName(destFilename);
        fileChooser.setTitle("Select file to save");
        return fileChooser.showSaveDialog(fileNameLabel.getScene().getWindow());
    }

    private File chooseFile() {
        var fileChooser = new FileChooser();
        fileChooser.setTitle("Select file to encrypt");
        return fileChooser.showOpenDialog(fileNameLabel.getScene().getWindow());
    }

    public void onDecryptButtonClick(ActionEvent actionEvent) {
        if (sourceFile == null) {
            sourceFile = chooseFile();
            if (sourceFile != null) {
                fileNameLabel.setText(String.format("Source: %s", sourceFile.getName()));
                System.out.printf("Source: %s\n", sourceFile);
            } else {
                System.out.println("No file selected.");
                cleanAll();
                return;
            }
        }

        byte[] keyBytes;
        byte[] ivBytes;

        var passwordDialog = new PasswordDialog();
        var result = passwordDialog.showAndWait();
        if (result.isPresent()) {
            System.out.printf("password: %s\n", result.get());
            try {
                var kdf_data = CryptoUtil.kdf_scrypt(result.get().toCharArray());
                System.out.printf("kdf: %s\n", Hex.toHexString(kdf_data));
                keyBytes = Arrays.copyOfRange(kdf_data, 0, 16);
                ivBytes = Arrays.copyOfRange(kdf_data, 16, 32);
                System.out.printf("key: %s\n", Hex.toHexString(keyBytes));
                System.out.printf("iv : %s\n", Hex.toHexString(ivBytes));
            } catch (Exception e) {
                System.out.println(e.getMessage());
                cleanAll();
                return;
            }
        } else {
            return;
        }

        var sourceFilename = sourceFile.getName();
        var filenameParts = sourceFilename.split("\\.");

        String destFilename;

        if (filenameParts.length < 3 || !filenameParts[filenameParts.length - 1].equals("enc") || filenameParts[filenameParts.length - 2].length() != 8) {
            System.out.printf("invalid filename: %s\n", sourceFilename);
            var alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Invalid filename");
            alert.setHeaderText("The file name is invalid, may not a encrypted file.");
            alert.setContentText("Do you want to decrypt anyway?");
            var ret = alert.showAndWait();
            if (ret.isPresent() && (ret.get() == ButtonType.OK)) {
                System.out.println("user choose to proceed anyway.");
            } else {
                System.out.println("user choose to cancel.");
                cleanAll();
                return;
            }
            destFilename = sourceFilename + ".dec";
        } else {
            destFilename = sourceFilename.substring(0, sourceFilename.length() - ".00000000.enc".length());
        }

        var ivSubStr = Hex.toHexString(Arrays.copyOfRange(ivBytes, 0, 4));
        if (filenameParts.length >= 3 && !filenameParts[filenameParts.length - 2].equals(ivSubStr)) {
            System.out.printf("invalid iv sub string: %s\n", sourceFilename);
            var alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Invalid filename");
            alert.setHeaderText("The password may be wrong.");
            alert.setContentText("Do you want to decrypt anyway?");
            var ret = alert.showAndWait();
            if (ret.isPresent() && (ret.get() == ButtonType.OK)) {
                System.out.println("user choose to proceed anyway.");
            } else {
                System.out.println("user choose to cancel.");
                cleanAll();
                return;
            }
        }

        System.out.printf("dest filename: %s\n", destFilename);

        var saveFile = saveFile(destFilename);
        if (saveFile != null) {
            fileNameLabel.setText(String.format("Encrypt: %s", saveFile));
            System.out.printf("Encrypt to save: %s\n", saveFile);
        } else {
            System.out.println("No file selected.");
            return;
        }

        try {
            var processor = new FileProcessor(keyBytes, ivBytes);
            processor.setFile(sourceFile, saveFile);
            processor.setOnSucceeded(wse -> {
                System.out.println("worker done.");
                sourceFile = null;
                fileNameLabel.setText("worker done.");
                progressBar.progressProperty().unbind();
                progressBar.setProgress(0);
            });
            processor.setOnFailed(wse -> wse.getSource().getException().printStackTrace());
            progressBar.progressProperty().unbind();
            progressBar.progressProperty().bind(processor.progressProperty());
            var worker = new Thread(processor);
            Thread.UncaughtExceptionHandler handler = (t, e) -> System.out.println(e.getMessage());
            worker.setUncaughtExceptionHandler(handler);
            worker.setDaemon(true);
            worker.start();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void cleanAll() {
        sourceFile = null;
        fileNameLabel.setText("");
    }
}