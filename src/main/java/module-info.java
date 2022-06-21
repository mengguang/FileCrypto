module cn.learndevops.filecrypto {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires org.bouncycastle.provider;

    opens cn.learndevops.filecrypto to javafx.fxml;
    exports cn.learndevops.filecrypto;
}