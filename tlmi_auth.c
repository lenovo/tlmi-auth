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
#include "tlmi_crypto.h"

#define PROG_VER      "V1.0.1"
#define TLMI_ADMIN "/sys/class/firmware-attributes/thinklmi/authentication/Admin"
#define TLMI_ATTR "/sys/class/firmware-attributes/thinklmi/attributes"

#define WMI_UPDATE_CERT "Lenovo_UpdateBiosCertificate"
#define WMI_CLEAR_CERT  "Lenovo_ClearBiosCertificate"
#define WMI_SET_ATTR    "Lenovo_SetBiosSettingEx"
#define WMI_SAVE_ATTR   "Lenovo_SaveBiosSettingsEx"
#define WMI_CERT2PASS   "Lenovo_ChangeBiosCertificateToPassword"

static char *default_outfile = "thinklmi.sh";

static void usage(void)
{
	fprintf(stderr, "Usage: tlmi-auth command [option]\n");
	fprintf(stderr, "Where commands are\n");
	fprintf(stderr, "  setcert -c cert.pem -p passwd                  - Set installed certificate\n");
	fprintf(stderr, "  updatecert -c cert.pem -k privkey.pem          - Update installed certificate\n");
	fprintf(stderr, "  clearcert -s serial -k privkey.pem             - Clear installed certificate\n");
	fprintf(stderr, "  attribute -a attribute -v value -k privkey.pem - Set attribute to given value\n");
	fprintf(stderr, "  cert2pass -p passwd -k privkey.pem             - Go from certificate to password authentication\n");
	fprintf(stderr, "  unlock -f request.txt -k privkey.pem           - Generate unlock code from request file.\n");
	fprintf(stderr, "  unlock -r request-string -k privkey.pem        - Generate unlock code from request string.\n");

	fprintf(stderr, "* -d option can be used instead of -c for DER formatted certificates.\n");
	fprintf(stderr, "* -o option specifies output filename.\n");
	fprintf(stderr, "* -u option can be used to specify password for the private key.\n");
	fprintf(stderr, "* -q option will inhibit all informative messages\n");
	fprintf(stderr, "* -h displays this message\n");
	//fprintf(stderr, "* -D option will print extra debug information\n");
	fprintf(stderr, "Lenovo ThinkLMI Authenticator Utility %s (built %s)\n", PROG_VER, __DATE__);
}

int main(int argc, char* argv[])
{
	int quiet = 0;
	int verbose = 0;
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
	while ((c = getopt (argc, argv, "c:d:p:k:s:a:v:f:r:u:o:hqD")) != -1) {
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
			case 'v':
				value = optarg;
				break;
			case 'f':
				reqfile = optarg;
				break;
			case 'r':
				reqstr = optarg;
				break;
			case 'u':
				set_key_passwd(optarg);
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'q':
				quiet = 1;
				set_printmode(1, 0);
				break;
			case 'D':
				verbose = 1;
				set_printmode(0, 1);
				break;
			case 'h':
				usage();
				return 0;
			case '?':
				if ((optopt == 'c') || (optopt == 'p') || (optopt == 'k') || (optopt == 's') || (optopt == 'a')
						|| (optopt == 'v') || (optopt == 'f') || (optopt == 'r') || (optopt == 'u'))
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

		fprintf(fp, "echo %s > %s/current_password\n", password, TLMI_ADMIN);
		fprintf(fp, "echo %s > %s/certificate\n", base64cert, TLMI_ADMIN);
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

		wmistr = (char *)malloc(strlen(WMI_UPDATE_CERT) + 1 + certLen + 1);
		if (!wmistr) {
			free(base64cert);
			return -1;
		}
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
		fprintf(fp, "echo %s > %s/signature\n", base64sig, TLMI_ADMIN);
		fprintf(fp, "echo %s > %s/certificate\n", base64cert, TLMI_ADMIN);
		fclose(fp);
		free(base64cert);
		free(base64sig);
	}
	else if (!strcmp(command, "clearcert")) {
		if (!sysserial || !key) {
			usage();
			exit(1);
		}
		wmistr = (char *)malloc(strlen(WMI_CLEAR_CERT) + 1 + strlen(sysserial) + 1);
		if (!wmistr)
			return -1;

		ret = sprintf(wmistr, "%s,%s", WMI_CLEAR_CERT, sysserial);
		if (ret < 0) {
			free(wmistr);
			return ret;
		}
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret)
			return ret;

		fprintf(fp, "echo %s > %s/signature\n", base64sig, TLMI_ADMIN);
		fprintf(fp, "echo '' > %s/certificate\n", TLMI_ADMIN);
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
		fprintf(fp, "echo %s > %s/save_signature\n", base64sig, TLMI_ADMIN);
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

		fprintf(fp, "echo %s > %s/signature\n", base64sig, TLMI_ADMIN);
		fprintf(fp, "echo %s > %s/%s/current_value\n", value, TLMI_ATTR, attribute);
		fclose(fp);
		free(base64sig);
	}
	else if (!strcmp(command, "cert2pass")) {
		if (!password || !key) {
			usage();
			exit(1);
		}
		wmistr = (char *)malloc(strlen(WMI_CERT2PASS) + 1 + strlen(password) + 1);
		if (!wmistr)
			return -1;

		ret = sprintf(wmistr, "%s,%s", WMI_CERT2PASS, password);
		if (ret < 0) {
			free(wmistr);
			return ret;
		}
		ret = wmi_sign(key, wmistr, &base64sig, &certLen);
		free(wmistr);
		if (ret)
			return ret;

		fprintf(fp, "echo %s > %s/signature\n", base64sig, TLMI_ADMIN);
		fprintf(fp, "echo %s > %s/cert_to_password\n", password, TLMI_ADMIN);
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
	} else {
		printf("Invalid command \'%s\'\n", command);
		usage();
		return -1;
	}
	print_info("Copy %s to target machine and run\n", outfile);

	return 0;
}

