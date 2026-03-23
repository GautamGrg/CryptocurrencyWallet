package wallet;

import java.util.List;

import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.ChildNumber;

public class BitcoinWallet implements Wallet {

    private final String seedPhrase;
    private final String address;
    private double balance = 0.0;

    public BitcoinWallet() {
        this.seedPhrase = MnemonicService.generateMnemonic();
        List<String> words = List.of(seedPhrase.split(" "));
        DeterministicSeed seed = new DeterministicSeed(words, null, "", 0);
        byte[] seedBytes = seed.getSeedBytes();
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);
        DeterministicKey childKey = HDKeyDerivation.deriveChildKey(masterKey, new ChildNumber(0));
        this.address = LegacyAddress.fromKey(MainNetParams.get(), childKey).toString();
    }

    public String getAddress() {
        return address;
    }

    public String getCurrency() {
        return "BTC";
    }

    public String getSeedPhrase() {
        return seedPhrase;
    }

    public double getBalance() {
        return balance;
    }
}
