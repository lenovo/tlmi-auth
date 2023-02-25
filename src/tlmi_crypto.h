/* tlmi_crypto.h */
/*
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
 */

#ifndef TLMI_CRYPTO_H
#define TLMI_CRYPTO_H

#define MAX_WMISTR  4096
#define MAX_PSWD    1024
#define SERIAL_LEN  24

void print_info(const char *format, ...);
void print_dbg(const char *format, ...);
void set_key_passwd(char* passwd);
void set_printmode(int quiet, int verbose);

int wmi_sign(char *keyfile, char *wmistr, char **base64sig, size_t *certLen);
int unlock_request(char *keyfile, char *request);
int unlock_file_request(char *keyfile, char *reqfile);
int cert_format_pem(char *certFile, char **base64cert, size_t *certLen);
int cert_format_der(char *certFile, char **base64cert, size_t *certLen);

#endif
