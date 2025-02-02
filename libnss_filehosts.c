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
#include <dirent.h>


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
	
	if(lookup_type == LOOKUP_FORWARD)
	{
		/* Aliases on forward lookup is not supported (otherwise all files had to be read up) */
		*((char**)(buffer+bufpos)) = NULL;
		result->h_aliases = (char**)(buffer+bufpos);
		bufpos += sizeof(char**);
		
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
		buffer[bufpos + strlen(hostname)] = '\0';
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
		   sizeof(char*) /* h_addr_list[1] (NULL) */ +
		   sizeof(char*) /* h_aliases[0] (NULL) */ > buflen)
		{
			goto buffer_error;
		}
		
		/* Copy requested IP address to the buffer */
		h_addr = (void*)(buffer+bufpos);
		memcpy(h_addr, req_addr, result->h_length);
		bufpos += result->h_length;
		/* h_addr_list[0] --> h_addr */
		*((char**)(buffer+bufpos)) = h_addr;
		/* h_addr_list --> h_addr_list[0] */
		result->h_addr_list = (char**)(buffer+bufpos);
		bufpos += sizeof(char**);
		/* h_addr_list[1] --> NULL */
		*((char**)(buffer+bufpos)) = NULL;
		bufpos += sizeof(char*);

		/* Initiate h_aliases array */
		result->h_aliases = (char**)(buffer + buflen - 1 /* "1" means sizeof(char**) here */);
		result->h_aliases[0] = NULL;
	}
	
	/* Construct file name */
	if(strlen(hostname) == 0 || strlen(hostname) > EXTIP_HOSTNAME_MAXLEN)
	{
		/* hostname is empty or too long */
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
				cnt++;
				
				/* Check buffer size */
				if(bufpos +
				   strlen(answer_buf)+1 /* hostname just found */ + 
				   cnt * sizeof(char*) /* h_aliases array at the end of buffer (canonical name does not need a slot there, but there is the terminating NULL) */ > buflen)
				{
					fclose(fh);
					goto buffer_error;
				}
				
				if(!reverse_canonical_name_found)
				{
					/* Canonical name := found hostname */
					strcpy(buffer+bufpos, answer_buf);
					result->h_name = buffer+bufpos;
					buffer[bufpos + strlen(answer_buf)] = '\0';
					bufpos += strlen(answer_buf)+1;
					reverse_canonical_name_found = 1;
				}
				else
				{
					strcpy(buffer+bufpos, answer_buf);
					buffer[bufpos + strlen(answer_buf)] = '\0';
					
					/* Move h_aliases pointer back in buffer */
					/* Aliases will be in reverse order in this way, but this does not matter */
					result->h_aliases = (char**)(result->h_aliases - 1 /* "1" means sizeof(char**) here */);
					result->h_aliases[0] = (char*)(buffer+bufpos);
					
					bufpos += strlen(answer_buf)+1;
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


static struct {
	DIR * dh;
} filehosts_enumerator;

enum nss_status _nss_filehosts_sethostent(void)
{
	filehosts_enumerator.dh = opendir(EXTIP_BASE_PATH);
	if(filehosts_enumerator.dh == NULL) return NSS_STATUS_TRYAGAIN;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_filehosts_gethostent_r(
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	struct dirent *dent;
	enum LookupType lookup_type;
	int af;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	void *address;
	
	if(filehosts_enumerator.dh == NULL)
	{
		*errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
	
	do {
		dent = readdir(filehosts_enumerator.dh);
		if(dent == NULL)
		{
			*errnop = NO_ADDRESS;
			return NSS_STATUS_NOTFOUND;
		}
	}
	while(dent->d_name[0] == '.');
	
	if(inet_pton(AF_INET6, dent->d_name, &ipv6))
	{
		lookup_type = LOOKUP_REVERSE;
		af = AF_INET6;
		address = &ipv6;
	}
	else if(inet_pton(AF_INET, dent->d_name, &ipv4))
	{
		lookup_type = LOOKUP_REVERSE;
		af = AF_INET;
		address = &ipv4;
	}
	else
	{
		lookup_type = LOOKUP_FORWARD;
		af = AF_UNSPEC;
		address = NULL;
	}
	
	return filehosts_gethostbyname_r(lookup_type, dent->d_name, address, result, buffer, buflen, errnop, h_errnop, af);
}

enum nss_status _nss_filehosts_endhostent(void)
{
	if(filehosts_enumerator.dh == NULL) return NSS_STATUS_UNAVAIL;
	if(closedir(filehosts_enumerator.dh)==0) filehosts_enumerator.dh = NULL;
	return NSS_STATUS_SUCCESS;
}
