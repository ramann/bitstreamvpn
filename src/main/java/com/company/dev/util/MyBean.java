package com.company.dev.util;

import com.company.dev.model.Purchase;
import com.company.dev.model.PurchaseDao;
import com.company.dev.model.Users;
import com.company.dev.model.UsersDao;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.*;
import org.springframework.stereotype.*;

import java.io.File;
import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.Date;

@Component
public class MyBean implements CommandLineRunner {
    public static WalletAppKit kit;

    @Autowired
    private UsersDao usersDao;

    @Autowired
    private PurchaseDao purchaseDao;

    public void run(String... args) {
        System.out.println("========= IS THIS THING ON =========");

        //NetworkParameters params;
        String filePrefix;
//        params = RegTestParams.get();

        filePrefix = "forwarding-service-regtest";
        Context context = new Context(RegTestParams.get());
        // Start up a basic app using a class that automates some boilerplate.
        kit = new WalletAppKit(context, new File("."), filePrefix);

/*        if (params == RegTestParams.get()) {
            // Regression test mode is designed for testing and development only, so there's no public network for it.
            // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.

        }*/
        kit.connectToLocalHost();

        // Download the block chain and wait until it's done.
        kit.startAsync();
        kit.awaitRunning();

        kit.wallet().addCoinsReceivedEventListener(new WalletCoinsReceivedEventListener() {
            @Override
            public void onCoinsReceived(Wallet w, Transaction tx, Coin prevBalance, Coin newBalance) {
                // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
                //
                // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
                Coin value = tx.getValueSentToMe(w);
                System.out.println("Received tx for " + value.toFriendlyString() + ": " + tx);
                System.out.println("Transaction will be forwarded after it confirms.");
                Users users = usersDao.findByUsername("mark"); //principal.getName()
                Date d = new Date();

                Purchase p = new Purchase(new Timestamp(d.getTime()), new BigDecimal(value.getValue()).movePointLeft(Coin.SMALLEST_UNIT_EXPONENT), kit.wallet().currentReceiveAddress().toString(), users);

                try {
                    purchaseDao.save(p);
                } catch (Exception ex) {
                    System.out.println("Error creating the purchase: " + ex.toString());
                }


                // Wait until it's made it into the block chain (may run immediately if it's already there).
                //
                // For this dummy app of course, we could just forward the unconfirmed transaction. If it were
                // to be double spent, no harm done. Wallet.allowSpendingUnconfirmedTransactions() would have to
                // be called in onSetupCompleted() above. But we don't do that here to demonstrate the more common
                // case of waiting for a block.
                Futures.addCallback(tx.getConfidence().getDepthFuture(1), new FutureCallback<TransactionConfidence>() {
                    @Override
                    public void onSuccess(TransactionConfidence result) {
                        //forwardCoins(tx);
                        System.out.println("Some coins were received");

                        p.setDateConfirm1(new Timestamp(new Date().getTime()));
                        try {
                            purchaseDao.save(p);
                        } catch (Exception ex) {
                            System.out.println("Error save confirmation 1: " + ex.toString());
                        }
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        // This kind of future can't fail, just rethrow in case something weird happens.
                        throw new RuntimeException(t);
                    }
                });
            }
        });
    }


}