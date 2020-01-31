#!/usr/bin/env groovy

package com.wolfssl

class AbiReportCheck {


    static void main(String[] args) {

        File reportFile = new File(args.size() ? args[0] : "./report.xml")
        if (!reportFile.exists()) System.exit(1)

        def abi = [
            "wc_ecc_free",
            "wc_ecc_init_ex",
            "wc_ecc_key_free",
            "wc_ecc_key_new",
            "wc_ecc_make_key_ex",
            "wc_ecc_sign_hash",
            "wc_rng_new",
            "wc_rng_free",
            "wolfSSL_CTX_SetDevId",
            "wolfSSL_CTX_SetEccSignCb",
            "wolfSSL_CTX_SetMinVersion",
            "wolfSSL_CTX_UseSNI",
            "wolfSSL_CTX_free",
            "wolfSSL_CTX_load_verify_locations",
            "wolfSSL_CTX_new",
            "wolfSSL_CTX_set_session_cache_mode",
            "wolfSSL_CTX_set_timeout",
            "wolfSSL_CTX_use_PrivateKey_file",
            "wolfSSL_CTX_use_certificate_chain_file",
            "wolfSSL_CTX_use_certificate_file",
            "wolfSSL_Cleanup",
            "wolfSSL_Init",
            "wolfSSL_SetDevId",
            "wolfSSL_UseALPN",
            "wolfSSL_UseSNI",
            "wolfSSL_X509_NAME_oneline",
            "wolfSSL_X509_free",
            "wolfSSL_X509_get_issuer_name",
            "wolfSSL_X509_get_next_altname",
            "wolfSSL_X509_get_subject_name",
            "wolfSSL_X509_load_certificate_file",
            "wolfSSL_X509_notAfter",
            "wolfSSL_X509_notBefore",
            "wolfSSL_check_domain_name",
            "wolfSSL_connect",
            "wolfSSL_flush_sessions",
            "wolfSSL_free",
            "wolfSSL_get_error",
            "wolfSSL_get_peer_certificate",
            "wolfSSL_get_session",
            "wolfSSL_get_sessionID",
            "wolfSSL_new",
            "wolfSSL_pending",
            "wolfSSL_read",
            "wolfSSL_set_fd",
            "wolfSSL_set_session",
            "wolfSSL_set_timeout",
            "wolfSSL_shutdown",
            "wolfSSL_use_PrivateKey_file",
            "wolfSSL_use_certificate_chain_file",
            "wolfSSL_use_certificate_file",
            "wolfSSL_write",
            "wolfTLSv1_2_client_method",
            "wolfTLSv1_3_client_method",
        ] as Set
        def check = [] as Set

        def xml = new XmlParser()
        def report = xml.parse(reportFile)

        report.report.problems_with_symbols.each { problem->
            problem.header.each { header->
                header.library.symbol.each { symbol->
                    check.add(symbol['@name'])
                }
            }
        }

        def result = abi.intersect(check)

        if (result.size() != 0) {
            println result
            System.exit(2)
        }

    }

}
