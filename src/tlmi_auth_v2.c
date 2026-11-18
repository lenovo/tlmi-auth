/*
 * Lenovo UEFI Authenticator Utility
 *
 *  Copyright @ 2022 Lenovo. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *  
 */

#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "tlmi_crypto.h"

#ifndef TLMI_PROG_VER
#define TLMI_PROG_VER   "0.0.2"
#endif

#define TLMI_ADMIN "/sys/class/firmware-attributes/thinklmi/authentication/Admin"
#define TLMI_SYSTEM "/sys/class/firmware-attributes/thinklmi/authentication/System"
#define TLMI_ATTR "/sys/class/firmware-attributes/thinklmi/attributes"

#define WMI_UPDATE_CERT "UpdateBiosCertificate"
#define WMI_CLEAR_CERT  "ClearBiosCertificate"
#define WMI_SET_ATTR    "SetBiosSetting"
#define WMI_SAVE_ATTR   "SaveBiosSettings"
#define WMI_CERT2PASS   "ChangeBiosCertificateToPassword"
#define WMI_CERT2PASS_TC "Lenovo_ChangeCertificateToSvp"
#define WMI_CERTTHUMB   "BiosCertificateThumbprint"

#define WMI_ADMIN_USER  "SVC" /* AKA SuperVisor */
#define WMI_SYSTEM_USER "SMC"

static char *default_user = "admin";
static char *default_outfile = "thinklmi.sh";

static void usage(void)
{
	fprintf(stderr, "Usage: tlmi-auth-v2 command [option]\n");
	fprintf(stderr, "Where commands are\n");
	fprintf(stderr, "  setcert -c cert.pem -p passwd                  - Set installed certificate\n");
	fprintf(stderr, "  updatecert -c cert.pem -k privkey.pem          - Update installed certificate\n");
	fprintf(stderr, "  clearcert -s serial -k privkey.pem             - Clear installed certificate\n");
	fprintf(stderr, "  attribute -a attribute -v value -k privkey.pem - Set attribute to given value\n");
	fprintf(stderr, "  cert2pass -p passwd -k privkey.pem             - Go from certificate to password authentication\n");
	fprintf(stderr, "  unlock -f request.txt -k privkey.pem           - Generate unlock code from request file.\n");
	fprintf(stderr, "  unlock -r request-string -k privkey.pem        - Generate unlock code from request string.\n");
	fprintf(stderr, "  thumbprint -# hash-algorithm -k privkey.pem    - Get certificate thumbprint\n");

	fprintf(stderr, "* -u option specifes the user - \"admin\" or \"system\". \"%s\" user is default.\n", default_user);
	fprintf(stderr, "* -d option can be used instead of -c for DER formatted certificates.\n");
	fprintf(stderr, "* -o option specifies output filename.\n");
	fprintf(stderr, "* -z option specifies private key password if required.\n");
	fprintf(stderr, "* -q option will inhibit all informative messages\n");
	fprintf(stderr, "* -h displays this message\n");
	//fprintf(stderr, "* -D option will print extra debug information\n");
	fprintf(stderr, "Lenovo ThinkLMI Authenticator V2 Utility version %s (built %s)\n", TLMI_PROG_VER, __DATE__);
}

static char * determine_user_file(char *user)
{
	if (!strcasecmp(user, "admin"))
		return TLMI_ADMIN;
	if (!strcasecmp(user, "system"))
		return TLMI_SYSTEM;
	return TLMI_ADMIN;
}

static char * determine_user_type(char *user)
{
	if (!strcasecmp(user, ""))
		return NULL;
	if (!strcasecmp(user, "admin"))
		return WMI_ADMIN_USER;
	if (!strcasecmp(user, "system"))
		return WMI_SYSTEM_USER;
	return WMI_ADMIN_USER;
}

int main(int argc, char* argv[])
{
	char *command = NULL;
	char *cert = NULL;
	char *key = NULL;
	char *password = NULL;
	char *sysserial = NULL;
	char *attribute = NULL;
	char *value = NULL;
	char *reqfile = NULL;
	char *reqstr = NULL;
	char *outfile= NULL;
	char *user=NULL;
	char *algorithm=NULL;
	int c;
	int ret = 0;
	FILE *fp;
	char *base64cert = NULL;
	char *base64sig= NULL;
	char *wmistr = NULL;
	bool der_cert = false;
	size_t certLen = 0;

	if (argc < 2) {
		usage();
		return 0;
	}

	command = argv[1];
	set_printmode(0, 0);
	opterr = 0;
	while ((c = getopt (argc, argv, "c:d:p:k:s:a:v:f:r:#:u:o:hqD")) != -1) {
		switch (c) {
			case 'c':
				cert = optarg;
				break;
			case 'd': /*DER formatted certificate */
				cert = optarg;
				der_cert = true;
				break;
			case 'p':
				password = optarg;
				break;
			case 'k':
				key = optarg;
				break;
			case 's':
				sysserial = optarg;
				break;
			case 'a':
				attribute = optarg;
				break;
			case 'u':
				user = optarg;
				break;
			case 'v':
				value = optarg;
				break;
			case 'f':
				reqfile = optarg;
				break;
			case 'r':
				reqstr = optarg;
				break;
			case '#':
				algorithm = optarg;
				break;
			case 'z':
				set_key_passwd(optarg);
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'q':
				set_printmode(1, 0);
				break;
			case 'D':
				set_printmode(0, 1);
				break;
			case 'h':
				usage();
				return 0;
			case '?':
				if ((optopt == 'c') || (optopt == 'p') || (optopt == 'k') || (optopt == 's') || (optopt == 'a')
						|| (optopt == 'v') || (optopt == 'f') || (optopt == 'r') || (optopt == 'u') || (optopt == '#'))
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n",	optopt);
				return -1;
			default:
				usage();
				return 0;
		}
	}

	/* If user is not provided use default user */
	if (!user)
		user = default_user;

	/* Create output file for thinklmi commands */
	if (!outfile)
		outfile = default_outfile;

	fp = fopen(outfile, "w");
	if (!fp) {
		fprintf(stderr, "cannot open %s\n", outfile);
		return -1;
	}
	fprintf(fp, "#!/bin/bash\n");

	if (!strcmp(command, "setcert")) {
		if (!cert || !password) {
			usage();
			exit(1);
		}
		if (der_cert)
			ret = cert_format_der(cert, &base64cert, &certLen);
		else
			ret = cert_format_pem(cert, &base64cert, &certLen);
		if (ret)
			return ret;

		fprintf(fp, "echo \"%s\" > %s/current_password\n", password, determine_user_file(user));
		fprintf(fp, "echo %s > %s/certificate\n", base64cert, determine_user_file(user));
		fclose(fp);
		free(base64cert);
	}
	else if (!strcmp(command, "updatecert")) {
		if (!cert || !key) {
			usage();
			exit(1);
		}
		if (der_cert)
			ret = cert_format_der(cert, &base64cert, &certLen);
		else
			ret = cert_format_pem(cert, &base64cert, &certLen);
		if (ret)
			return ret;

		wmistr = (char *)malloc(strlen(WMI_ADMIN_USER) + 1 + strlen(WMI_UPDATE_CERT) + 1 + certLen + 1);
		if (!wmistr) {
			free(base64cert);
			return -1;
		}
		if (determine_user_type(user))
			ret = sprintf(wmistr, "%s,%s,%s", WMI_UPDATE_CERT, determine_user_type(user), base64cert);
		else
			ret = sprintf(wmistr, "%s,%s", WMI_UPDATE_CERT, base64cert);
		if (ret < 0) {
			free(wmistr);
			free(base64cert);
			return ret;
		}

		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret) {
			free(base64cert);
			return ret;
		}
		fprintf(fp, "echo %s > %s/signature\n", base64sig, determine_user_file(user));
		fprintf(fp, "echo %s > %s/certificate\n", base64cert, determine_user_file(user));
		fclose(fp);
		free(base64cert);
		free(base64sig);
	}
	else if (!strcmp(command, "clearcert")) {
		if (!sysserial || !key) {
			usage();
			exit(1);
		}
		wmistr = (char *)malloc(strlen(WMI_ADMIN_USER) + 1 + strlen(WMI_CLEAR_CERT) + 1 + strlen(sysserial) + 1);
		if (!wmistr)
			return -1;

		if (determine_user_type(user))
			ret = sprintf(wmistr, "%s,%s,%s", WMI_CLEAR_CERT, determine_user_type(user), sysserial);
		else
			ret = sprintf(wmistr, "%s,%s", WMI_CLEAR_CERT, sysserial);
		if (ret < 0) {
			free(wmistr);
			return ret;
		}
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret)
			return ret;

		fprintf(fp, "echo %s > %s/signature\n", base64sig, determine_user_file(user));
		fprintf(fp, "echo '' > %s/certificate\n", determine_user_file(user));
		fclose(fp);
		free(base64sig);
	}
	else if (!strcmp(command, "attribute")) {
		if (!attribute || !value || !key) {
			usage();
			exit(1);
		}
		ret = wmi_sign(key, WMI_SAVE_ATTR, &base64sig, &certLen);
		if (ret)
			return ret;
		fprintf(fp, "echo %s > %s/save_signature\n", base64sig, determine_user_file(user));
		free(base64sig);

		wmistr = (char *)malloc(strlen(WMI_SET_ATTR) + 1 + strlen(attribute) + 1 + strlen(value) + 1);
		if (!wmistr)
			return -1;

		ret = sprintf(wmistr, "%s,%s,%s", WMI_SET_ATTR, attribute, value);
		if (ret < 0) {
			free(wmistr);
			return ret;
		}
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret)
			return ret;

		fprintf(fp, "echo %s > %s/signature\n", base64sig, determine_user_file(user));
		fprintf(fp, "echo %s > %s/%s/current_value\n", value, TLMI_ATTR, attribute);
		fclose(fp);
		free(base64sig);
	}
	else if (!strcmp(command, "cert2pass")) {
		char wmi_cert2pass[50];

		if (!password || !key) {
			usage();
			exit(1);
		}

		sprintf(wmi_cert2pass, WMI_CERT2PASS);
		wmistr = (char *)malloc(strlen(WMI_ADMIN_USER) + 1 + strlen(wmi_cert2pass) + 1 + strlen(password) + 1);
		if (!wmistr)
			return -1;

		if (determine_user_type(user))
			ret = sprintf(wmistr, "%s,%s,%s", wmi_cert2pass, determine_user_type(user), password);
		else
			ret = sprintf(wmistr, "%s,%s", wmi_cert2pass, password);
		if (ret < 0) {
			free(wmistr);
			return ret;
		}
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret)
			return ret;

		fprintf(fp, "echo %s > %s/signature\n", base64sig, determine_user_file(user));
		fprintf(fp, "echo \"%s\" > %s/cert_to_password\n", password, determine_user_file(user));
		fclose(fp);
		free(base64sig);
	}
	else if (!strcmp(command, "unlock")) {
		if (!key) {
			usage();
			exit(1);
		}
		if (!reqfile && !reqstr) {
			usage();
			exit(1);
		}
		if (reqfile)
			ret = unlock_file_request(key, reqfile);
		else
			ret = unlock_request(key, reqstr);
		printf("\n");
		if (ret)
			return ret;
	} else if (!strcmp(command, "thumbprint")) {
		if (!algorithm || !key) {
			usage();
			exit(1);
		}
		wmistr = (char *)malloc(strlen(WMI_ADMIN_USER) + 1 + strlen(WMI_CERTTHUMB) + 1 + strlen(algorithm) + 1);
		if (!wmistr) {
			free(base64cert);
			return -1;
		}
		ret = sprintf(wmistr, "%s,%s,%s", WMI_CERTTHUMB, algorithm, determine_user_type(user));
		if (ret < 0) {
			free(wmistr);
			free(base64cert);
			return ret;
		}
		printf("Signing: %s\n", wmistr);
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret) {
			free(base64cert);
			return ret;
		}
		fprintf(fp, "echo %s > %s/signature\n", base64sig, determine_user_file(user));
		fprintf(fp, "cat > %s/certificate_thumbprint\n", determine_user_file(user));
		fclose(fp);
		free(base64cert);
		free(base64sig);
	} else {
		printf("Invalid command \'%s\'\n", command);
		usage();
		return -1;
	}
	print_info("Copy %s to target machine and run\n", outfile);

	return 0;
}

