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

#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

struct ipaddr {
	int af;
	struct in_addr ip4;
	struct in6_addr ip6;
};

enum LookupType {
	LOOKUP_FORWARD = 1,
	LOOKUP_REVERSE,
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
	enum LookupType lookup_type,
	const char *hostname,
	const void *req_addr,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop,
	int req_af)
{
	size_t bufpos = 0;
	size_t astart;
	struct ipaddr extip;
	FILE *fh;
	char extip_file[strlen(EXTIP_BASE_PATH)+EXTIP_HOSTNAME_MAXLEN+1];
	char answer_buf[EXTIP_HOSTNAME_MAXLEN+1];
	int cnt = 0;
	int reverse_canonical_name_found = 0;
	void* h_addr;
	
	
	
	/* We don't know the address family yet */
	result->h_addrtype = AF_UNSPEC;
	
	/* Alias names := none; we don't support aliases */
	*((char**)(buffer+bufpos)) = NULL;
	result->h_aliases = (char**)(buffer+bufpos);
	bufpos += sizeof(char*);
	
	if(lookup_type == LOOKUP_FORWARD)
	{
		/* Check buffer size */
		if(bufpos +
		   strlen(hostname)+1 /* canonical name string */ + 
		   sizeof(void*) /* possible alignment */ > buflen)
		{
			goto buffer_error;
		}
		
		/* Canonical name := requested hostname (copy) */
		strcpy(buffer+bufpos, hostname);
		result->h_name = buffer+bufpos;
		buffer[strlen(hostname)] = '\0';
		bufpos += strlen(hostname)+1;
		ALIGN(bufpos);
		astart = bufpos;
	}
	
	if(lookup_type == LOOKUP_REVERSE)
	{
		/* Address family is defined by caller */
		result->h_addrtype = req_af;
		result->h_length = (req_af == AF_INET6) ? sizeof(struct in6_addr) : sizeof(struct in_addr);
		
		/* Check buffer size */
		if(bufpos +
		   result->h_length /* requested IP address */ +
		   sizeof(char*) /* h_addr_list[0] */ +
		   sizeof(char*) /* h_addr_list[1] (NULL) */ > buflen)
		{
			goto buffer_error;
		}
		
		/* Add requested IP to the address list */
		h_addr = (void*)(buffer+bufpos);
		memcpy(h_addr, req_addr, result->h_length);
		bufpos += result->h_length;
		*((char**)(buffer+bufpos)) = h_addr;
		result->h_addr_list = (char**)(buffer+bufpos);
		bufpos += sizeof(char*);
		/* Add list terminating NULL */
		*((char**)(buffer+bufpos)) = NULL;
		bufpos += sizeof(char*);
	}
	
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
		if(fscanf(fh, "%"STR(EXTIP_HOSTNAME_MAXLEN)"s", &answer_buf) == 1)
		{
			if(lookup_type == LOOKUP_FORWARD)
			{
				if(parseIpStr(answer_buf, &extip) == SUCCESS)
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
						
						if(bufpos + 
						   result->h_length /* current address */ + 
						   (cnt+1) * sizeof(char*) /* all h_addr_list pointers so far added below */ > buflen)
						{
							fclose(fh);
							goto buffer_error;
						}
						
						memcpy(buffer+bufpos, ipaddr_get_binary_addr(&extip), result->h_length);
						bufpos += result->h_length;
						cnt++;
					}
				}
			}
			
			if(lookup_type == LOOKUP_REVERSE)
			{
				/* Check buffer size */
				if(bufpos +
				   strlen(answer_buf)+1 /* hostname just found */ + 
				   sizeof(void*) /* possible alignment */ > buflen)
				{
					fclose(fh);
					goto buffer_error;
				}
				
				cnt++;
				
				if(!reverse_canonical_name_found)
				{
					/* Canonical name := found hostname */
					strcpy(buffer+bufpos, answer_buf);
					result->h_name = buffer+bufpos;
					buffer[strlen(answer_buf)] = '\0';
					bufpos += strlen(answer_buf)+1;
					ALIGN(bufpos);
					astart = bufpos;
				}
				else
				{
					// TODO: continue reading file and add further names as aliases
				}
				
				break; // TODO: wont need to break once aliases are supported
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
	
	if(lookup_type == LOOKUP_FORWARD)
	{
		result->h_addr_list = (char**)(buffer + bufpos);
		int n = 0;
		for(; n < cnt; n++)
		{
			result->h_addr_list[n] = (char*)(buffer + astart + n*result->h_length);
		}
		result->h_addr_list[n] = NULL;
	}
	
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
	return filehosts_gethostbyname_r(LOOKUP_FORWARD, hostname, NULL, result, buffer, buflen, errnop, h_errnop, AF_UNSPEC);
}

enum nss_status _nss_filehosts_gethostbyname2_r(
	const char *hostname,
	int req_af,
	struct hostent * result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	if (req_af != AF_INET && req_af != AF_INET6 && req_af != AF_UNSPEC)
	{
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		return filehosts_gethostbyname_r(LOOKUP_FORWARD, hostname, NULL, result, buffer, buflen, errnop, h_errnop, req_af);
	}
}

enum nss_status _nss_filehosts_gethostbyaddr_r(
	const void *address,
	socklen_t len,
	int req_af,
	struct hostent * result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	char address_as_string[INET6_ADDRSTRLEN];
	if(inet_ntop(req_af, address, address_as_string, sizeof(address_as_string)/sizeof(char)) == NULL)
	{
		*errnop = errno;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
	
	return filehosts_gethostbyname_r(LOOKUP_REVERSE, address_as_string, address, result, buffer, buflen, errnop, h_errnop, req_af);
}
