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
#include <stddef.h>
#include <stdio.h>
#include <string.h>


#define EXTIP_BASE_PATH "/var/run/firewall/"
#define EXTIP_BASE_PATH_LEN 18
#define EXTIP_HOSTNAME_MAXLEN 64

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

enum nss_status extip_gethostbyname_r(
	const char *name,
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
	char extip_file[EXTIP_BASE_PATH_LEN+EXTIP_HOSTNAME_MAXLEN+1];
	char ipbuf[INET6_ADDRSTRLEN];
	int af = 0;
	int cnt = 0;
	
	
	// TODO: check TLD ".localhost"
	if(strcmp(name, "extip.localhost")==0 || strcmp(name, "extipv4.localhost")==0) af = AF_INET;
	else if(strcmp(name, "extipv6.localhost")==0) af = AF_INET6;
	
	if(af != 0 && (req_af == af || req_af == 0))
	{
		/* Check buffer size */
		if(sizeof(char*) /* NULL pointer for aliases */ + strlen(name)+1 /* official name string */ + 8 /* possible alignment */ > buflen)
		{
			goto buffer_error;
		}
		
		/* Alias names -> none */
		*((char**) buffer) = NULL;
		result->h_aliases = (char**) buffer;
		idx = sizeof(char*);
		
		/* Official name -> copy requested hostname */
		strcpy(buffer+idx, name);
		result->h_name = buffer+idx;
		idx += strlen(name)+1;
		ALIGN(idx);
		astart = idx;
		
		result->h_addrtype = af;
		result->h_length = (af == AF_INET6) ? sizeof(struct in6_addr) : sizeof(struct in_addr);
		
		/* Read file containing external IPs */
		fh = fopen(extip_file, "r");
		if(fh == NULL)
		{
			warn("%s", extip_file);
			*errnop = EAGAIN;
			*h_errnop = NO_RECOVERY;
			return NSS_STATUS_TRYAGAIN;
		}
		
		while(!feof(fh))
		{
			if(fscanf(fh, "%s", &ipbuf) == 1)
			{
				if(parseIpStr(ipbuf, &extip) == 1)
				{
					if(extip.af == af)
					{
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
	}
	else
	{
		*errnop = EINVAL;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}
	
	buffer_error:
	warnx("Not enough buffer space at %s().", __func__);
	*errnop = ERANGE;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_extip_gethostbyname_r(
	const char *name,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	return extip_gethostbyname_r(name, result, buffer, buflen, errnop, h_errnop, 0);
}

enum nss_status _nss_extip_gethostbyname2_r(
	const char *name,
	int af,
	struct hostent * result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	if (af != AF_INET && af != AF_INET6)
	{
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		return extip_gethostbyname_r(name, result, buffer, buflen, errnop, h_errnop, af);
	}
}

