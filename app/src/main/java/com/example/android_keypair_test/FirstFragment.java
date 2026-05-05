package com.example.android_keypair_test;

import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import com.example.android_keypair_test.databinding.FragmentFirstBinding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class FirstFragment extends Fragment {

    public static final String KEY_ALIAS = "device1cert0";


    private FragmentFirstBinding binding;

    private PrivateKey key;
    private X509Certificate[] certificateChain;

    @Override
    public View onCreateView(
            @NonNull LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState
    ) {

        binding = FragmentFirstBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        binding.buttonInstallKey.setOnClickListener(v -> this.onInstallKeyClicked(v));
        binding.buttonGrantKey.setOnClickListener(v -> this.onGrantKeyClicked());
        binding.buttonGetKey.setOnClickListener(v -> this.onGetKeyClicked());
        binding.buttonSign.setOnClickListener(v -> this.onSignClicked());
        binding.buttonVerify.setOnClickListener(v -> this.onVerifyClicked());
    }

    /// Open a file picker, allowing the user to install a .pkcs12 file containing device cert and
    /// private key. We won't have to do this in production, because the key will be pre-installed.
    private void onInstallKeyClicked(@NonNull View view) {
        var activity = this.getActivity();

        var intent = KeyChain.createInstallIntent();
        activity.startActivityForResult(intent, 0, null);
    }

    /// Open a chooser, allowing the user to select a private key. We think this will be done for us
    /// in production, via DevicePolicyManager.grantKeyPairToApp().
    private void onGrantKeyClicked() {
        KeyChain.choosePrivateKeyAlias(
            this.getActivity(),
            (alias) -> System.out.println("key granted:" + alias),
            null, null, null, null
        );
    }

    /// Get hold of (a handle to) the key, and a copy of the cert chain, and stash them in memory.
    ///
    /// This is a separate step because it is async and has to be done in a thread. We want to
    /// demonstrate that we can do this once at startup, and then the rest can be synchronous.
    private void onGetKeyClicked() {
        var context = this.getContext();

        new Thread(() -> {
            try {
                key = KeyChain.getPrivateKey(context, KEY_ALIAS);
                certificateChain = KeyChain.getCertificateChain(context, KEY_ALIAS);
            } catch (InterruptedException | KeyChainException e) {
                throw new RuntimeException(e);
            }

        }).start();
    }

    /// Sign a secret using the private key we grabbed earlier.
    private void onSignClicked() {
        try {
            var providers = Security.getProviders();
            var provider = providers[0];
            System.out.println("provider: " + provider.getName());

            var signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update("Hello world".getBytes(StandardCharsets.UTF_8));
            var sig = signature.sign();
            System.out.println("sig: " + sig);
            System.out.println("cert chain:");
            for (var cert: certificateChain) {
                System.out.println("  " + cert.getSubjectDN());
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /// Verify that the certificate is valid and issued by the right trust root
    private void onVerifyClicked() {
        try {
            // The cert chain, as it would be received in the `certificates` key in the `signature`.
            //
            // NB requires the leaf certificate first, followed by intermediate certs. We don't
            // have an intermediate CA, so there is only a leaf cert here.
            var certChainPEM =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIEKjCCAhKgAwIBAgIBADANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVSzEP\n" +
                "MA0GA1UECAwGTG9uZG9uMRMwEQYDVQQKDAplbGVtZW50LmlvMRAwDgYDVQQDDAd0\n" +
                "ZXN0LWNhMB4XDTI2MDQyNzEzMzIzNVoXDTI3MDQyNzEzMzIzNVowKDEmMCQGCSqG\n" +
                "SIb3DQEJARYXdmRoLXg1MDl0ZXN0QG1hdHJpeC5vcmcwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQCzMke0NO4fXtAnkvqqc9PHcf6tMAB7P7+xjWDTpKfJ\n" +
                "PHohC7IzTNR8u1+Oz76fCLq0bIWDbXS570YoA9hlj6UCH5a/+4NhsNYKTapbUVfq\n" +
                "LVk41oNKAFt7brKZ8tkvAG9GCSKztrc3xAG5+QmiEoVY1XSShz3WuD94LIp3me2R\n" +
                "doQcgSP3Gb6zIhpE8sI4MMRsyjU/k822SfiKOqrWKa+HuXTmNDC2UeCTj2++y0e4\n" +
                "s2IRrniOjM84Ci2mMhv/L6cpwwhyI1PsL28tGAX1NhEdVdrQxcOyhh3T9Q2er8J1\n" +
                "kJsfOEmLecNutiSi+mdYbY1pKc60St4KVBE89zAWIg/FAgMBAAGjQjBAMB0GA1Ud\n" +
                "DgQWBBQdCjaG9Xzjyxv9S7xlM1ryXhGyWTAfBgNVHSMEGDAWgBTYXpGaF/DDWxPb\n" +
                "dUJ9ITea3z6WETANBgkqhkiG9w0BAQsFAAOCAgEAhhIcWrFaAd4DuDlHHoqmL9rs\n" +
                "sLn3rx+v4Et+GRV0EjMIOX+tTPO3mUCUb8Ifvk8cC3fucoClKVG8snzIir4eUFOx\n" +
                "d6M7+GAoTLkh8V8XAre3Xo9O2vxB2V8m3IO8Sbnht9aWj9FeMB5Pb9yzTFr8GZPf\n" +
                "7jky+o9R9lrIrURprKBehStYTaNj5YIjYxDXwy+64yXyrckhA8vioFpUFz/CBQMz\n" +
                "B4DwEZRjtFNDxNKA/LcoSnTRfoTpclZIUtJ7YX/qC98QUleuNzpGHM3/59Tn7lzt\n" +
                "ykuWvCAFc3f1nELrEe2ffhCs5M9HNBtGJZ21iEK4LaIu4PBgRTuXDXfsZpC02VKi\n" +
                "s8S9G+er9IUyLpJ1dajY2jXhJuUvmcFLltlzUPYocWcQVVFFAkrrHnew5NzZUPOD\n" +
                "+LQYjNFszITmFc6V49Df23d/kDK+4QzpdtjEf+hjWdDtUDLsAvc48RylwoSIwxn+\n" +
                "3poImhlL5uqHuyQfQqnEVo/DrV44qi3Qv+cBzC+DQ0SQQJ89keWNTGGAVRggY6lX\n" +
                "iQOKT/LtaDO8mtCwY9GT5ZqjynCnLygdG+GgE7sBaRhoj5FFIaXHD83Gcwpv/JI6\n" +
                "giqgGwii4W8KvNkR/k1Z6C9+RvENbluqMRbQ3CXVNDbyU1MB6ZliRGTtbZvL0bd1\n" +
                "/F4LixSyyHVXMUn4/1Q=\n" +
                "-----END CERTIFICATE-----";


//            validateCertsViaCheckServerTrusted(certChainPEM);
            validateCertsViaCertPathValidator(certChainPEM);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

/*
    // Verification option 1: TrustManager.checkServerTrusted.
    //
    // This works ok provided we configure the app to trust user certs, via
    // `networkSecurityConfig` in the manifest.
    private static void validateCertsViaCheckServerTrusted(String certChainPEM) throws CertificateException {
        // Parse the certs into an array
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        var certStream = new ByteArrayInputStream(certChainPEM.getBytes(StandardCharsets.UTF_8));
        var certs = cf.generateCertificates(certStream);
        var certArray = certs.toArray(new X509Certificate[certs.size()]);

        // Check the trust path
        var trustManager = getTrustManager();
        trustManager.checkServerTrusted(certArray, certArray[0].getPublicKey().getAlgorithm());
        System.out.println("Server is trusted");
    }

    static X509TrustManager getTrustManager() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            // Just use the default keystore
            tmf.init((KeyStore) null);

            TrustManager[] trustManagers = tmf.getTrustManagers();
            for (var t: trustManagers) {
                if (t instanceof X509TrustManager) {
                    return (X509TrustManager) t;
                }
            }
            throw new IllegalStateException("No X509TrustManager found");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
*/

    // Verification option 2: CertPathValidator.validate.
    //
    // This gives us fine control over exactly which certificates are trusted, and furthermore
    // doesn't require us to configure the app as a whole to trust user CAs.
    private static void validateCertsViaCertPathValidator(String certChainPEM) throws GeneralSecurityException, IOException {
        // Parse the certs into a cert path
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        var certStream = new ByteArrayInputStream(certChainPEM.getBytes(StandardCharsets.UTF_8));
        var certs = cf.generateCertificates(certStream);
        var certPath = cf.generateCertPath(new ArrayList<>(certs));

        // Set up our trust anchors, based on certificates in the store
        var keystore = KeyStore.getInstance("AndroidCAStore");
        keystore.load(null);
        var anchors = new HashSet<TrustAnchor>();
        var aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keystore.isCertificateEntry(alias)) {
                X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                if (cert.getSubjectDN().toString().equals("CN=test-ca, O=element.io, ST=London, C=UK")) {
                    anchors.add(new TrustAnchor(cert, null));
                }
            }
        }

        // Validate the cert path
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);

        System.out.println("Validated via Trust anchor " + result.getTrustAnchor().getTrustedCert().getSubjectDN());
    }


    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
}
