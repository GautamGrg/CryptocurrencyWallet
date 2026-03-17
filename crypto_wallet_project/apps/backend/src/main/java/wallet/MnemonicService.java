package wallet;

import java.util.*;
import java.security.*;

import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;

public class MnemonicService {

    private static final SecureRandom random = new SecureRandom();

    public static String generateMnemonic() {
        try {
            byte[] entropy = new byte[32];
            random.nextBytes(entropy);

            List<String> words = MnemonicCode.INSTANCE.toMnemonic(entropy);
            return String.join(" ", words);
        } catch (MnemonicException exc) {
            throw new RuntimeException("Failed to generate BIP39 mnemonic seed phrase: " + exc);
        }
    }

    public static boolean validateMnemonic(String mnemonic) {
        try {
            List<String> words = List.of(mnemonic.split(" "));
            org.bitcoinj.crypto.MnemonicCode.INSTANCE.check(words);
            return true;
        } catch (Exception exc) {
            return false;
        }
    }
}
