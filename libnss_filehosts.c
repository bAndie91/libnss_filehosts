/*  
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file incorporates some code from the nss-mdns module © 2004 
 *  Lennart Poettering; nss-gw-name module © 2010,2012 Joachim Breitner.
 */

#include <arpa/inet.h>
#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


#define EXTIP_BASE_PATH "/etc/filehosts/"
#define EXTIP_HOSTNAME_MAXLEN 255
#define SUCCESS 1

struct ipaddr {
	int af;
	struct in_addr ip4;
	struct in6_addr ip6;
};


#define ALIGN(idx) do { \
  if (idx % sizeof(void*)) \
    idx += (sizeof(void*) - idx % sizeof(void*)); /* Align on 32 bit boundary */ \
} while(0)


int parseIpStr(const char *str, struct ipaddr *addr)
{
	/* Return: 1 on success */
	int ok;
	
	addr->af = AF_INET;
	ok = inet_pton(AF_INET, str, &(addr->ip4));
	if(ok == -1) perror("inet_pton");
	if(ok != 1)
	{
		addr->af = AF_INET6;
		ok = inet_pton(AF_INET6, str, &(addr->ip6));
		if(ok == -1) perror("inet_pton");
	}
	return ok;
}

void* ipaddr_get_binary_addr(struct ipaddr *addr)
{
	if(addr->af == AF_INET) return &(addr->ip4.s_addr);
	if(addr->af == AF_INET6) return &(addr->ip6.__in6_u);
	return NULL;
}

enum nss_status filehosts_gethostbyname_r(
	const char *hostname,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop,
	int req_af)
{
	size_t idx, astart;
	struct ipaddr extip;
	FILE *fh;
	char extip_file[strlen(EXTIP_BASE_PATH)+EXTIP_HOSTNAME_MAXLEN+1];
	char ipbuf[INET6_ADDRSTRLEN];
	int cnt = 0;
	
	
	/* Check buffer size */
	if(sizeof(char*) /* NULL pointer for aliases */ + strlen(hostname)+1 /* official name string */ + 8 /* possible alignment */ > buflen)
	{
		goto buffer_error;
	}
	
	/* We don't know the address family yet */
	result->h_addrtype = AF_UNSPEC;
	
	/* Alias names := none */
	*((char**) buffer) = NULL;
	result->h_aliases = (char**) buffer;
	idx = sizeof(char*);
	
	/* Canonical name -> copy requested hostname */
	strcpy(buffer+idx, hostname);
	result->h_name = buffer+idx;
	idx += strlen(hostname)+1;
	ALIGN(idx);
	astart = idx;
	
	/* Construct file name */
	if(strlen(hostname) > EXTIP_HOSTNAME_MAXLEN)
	{
		/* hostname is too long */
		goto host_not_found;
	}
	if(snprintf(extip_file, strlen(EXTIP_BASE_PATH) + EXTIP_HOSTNAME_MAXLEN + 1, "%s%s", EXTIP_BASE_PATH, hostname) != strlen(EXTIP_BASE_PATH) + strlen(hostname))
	{
		abort();
	}
	
	/* Read IP addresses from file */
	fh = fopen(extip_file, "r");
	if(fh == NULL)
	{
		if(errno == ENOENT) goto host_not_found;
		
		warn("%s", extip_file);
		*errnop = EAGAIN;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}
	
	while(!feof(fh))
	{
		if(fscanf(fh, "%s", &ipbuf) == 1)
		{
			if(parseIpStr(ipbuf, &extip) == SUCCESS)
			{
				if(req_af == AF_UNSPEC)
				{
					/* Let's take the first found IP's AF if the caller has not specified any */
					req_af = extip.af;
				}
				if(extip.af == req_af)
				{
					if(result->h_addrtype == AF_UNSPEC)
					{
						/* Fill the AF fields if they have not been yet */
						result->h_addrtype = extip.af;
						result->h_length = (extip.af == AF_INET6) ? sizeof(struct in6_addr) : sizeof(struct in_addr);
					}
					
					if(idx + result->h_length + (cnt+1) * sizeof(char*) > buflen)
					{
						fclose(fh);
						goto buffer_error;
					}
					
					memcpy(buffer+idx, ipaddr_get_binary_addr(&extip), result->h_length);
					idx += result->h_length;
					cnt++;
				}
			}
		}
	}
	fclose(fh);
	
	if(cnt == 0)
	{
		host_not_found:
		*errnop = EINVAL;
		*h_errnop = NO_ADDRESS;
		return NSS_STATUS_NOTFOUND;
	}
	
	result->h_addr_list = (char**)(buffer + idx);
	int n = 0;
	for(; n < cnt; n++)
	{
		result->h_addr_list[n] = (char*)(buffer + astart + n*result->h_length);
	}
	result->h_addr_list[n] = NULL;
	
	return NSS_STATUS_SUCCESS;
	
	wrong_address_family:
	*errnop = EINVAL;
	*h_errnop = HOST_NOT_FOUND;
	return NSS_STATUS_NOTFOUND;
	
	buffer_error:
	warnx("Not enough buffer space at %s().", __func__);
	*errnop = ERANGE;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_filehosts_gethostbyname_r(
	const char *hostname,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	return filehosts_gethostbyname_r(hostname, result, buffer, buflen, errnop, h_errnop, 0);
}

enum nss_status _nss_filehosts_gethostbyname2_r(
	const char *hostname,
	int af,
	struct hostent * result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC)
	{
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		return filehosts_gethostbyname_r(hostname, result, buffer, buflen, errnop, h_errnop, af);
	}
}

