# RdkInterDeviceManager

RdkInterDeviceManager provides a mechanism to discover, advertise device capabilities, and manage RDK LAN devices. 

It implements robust authentication protocols using mTLS((mutual Transport Layer Security) and establishes a secure TLS  communication channel for encrypted data exchange between RDK routers and LAN devices.


## SETUP:

## systemd_units/ssl.conf:
	This file defines ssl the following parameters certifcates and key file paths used by RdkInterDeviceManager and rdk-xupnp.

	IDM_CERT_FILE - SSL Certificate file
	IDM_KEY_FILE  - SSL Private key file
	IDM_CA_FILE   - CA Certificate file
	IDM_CA_DIR    - CA Certificate path

	Make sure these files exist and contain valid SSL/TLS certificates before starting the RdkInterDeviceManager!

	If PKCS#12 certificate is used, implement appropriately changes to extract the certs w.r.t ssl.conf file as reference.

## Generic Openssl Commands to generate CA, Cert and Keys:

	1. Create Certificate Authority (CA) file.

		a. Generate CA private key.
		openssl genpkey -algorithm RSA -out idm_UPnP_CA.key -pkeyopt rsa_keygen_bits:2048

		b. Generate CA Certificate.
		openssl req -x509 -new -nodes -keyout idm_UPnP_CA.key -out idm_UPnP_CA -sha256 -days 365 -subj "/C=UK/ST=Essex/L=Brentwood/O=MyCompany CA/OU=IT Security/CN=Root CA"

	2. Generate Self Signed Certificate.

		a. Generate Private Key.
		openssl genpkey -algorithm RSA -out idm_xpki_key -pkeyopt rsa_keygen_bits:2048

		b. Generate Certificate Signing Request (CSR) file.
		openssl req -new -key idm_xpki_key -out idm_xpki.csr -subj "/C=UK/ST=Essex/L=Brentwood/O=MyCompany/OU=IT Operations/CN=idm_xpki_cert"

		c. Sign CSR using the CA.
		openssl x509 -req -in idm_xpki.csr -CA idm_UPnP_CA -CAkey idm_UPnP_CA.key -CAcreateserial -out idm_xpki_cert -days 365 -sha256

	3. Verify certificate using CA file.
		openssl verify -CAfile idm_UPnP_CA idm_xpki_cert - should return ok.

## Note:
	1. idm_UPnP_CA and idm_UPnP_CA.key files must remain same between any two given devices to trust the same CA.
	2. Install idm_UPnP_CA, idm_xpki_cert and idm_xpki_key in appropriate location (as per ssl.conf)

