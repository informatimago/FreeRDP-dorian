/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * $Id$
 */

#define __URI_C_

#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

#include "uri.h"
#include "error.h"
#include <errno.h>
#include "strings.h"

#include <freerdp/log.h>
#define TAG FREERDP_TAG("core.pkcs11.uri")

static const char *valid_urls[]=
		{"file:///","http://","https://","ftp://","ldap://",NULL};
/*
comodity functions
Analize provided pathname and check type
Returns 1 on true, 0 on false, -1 on error
*/

int is_uri(const char *path) {
	int n=0;
	if(is_empty_str(path)) return -1;
	while(valid_urls[n]) {
		if(strstr(path,valid_urls[n++])) return 1;
	}
	return 0;
}

static struct stat * stat_file(const char *path) {
	static struct stat buf;
	int res;
	const char *pt=path;
	if(is_empty_str(path)) return NULL;
	if (is_uri(path)) {
		if (!strstr(path,"file:///")) return NULL;
		pt=path+8;
	}
	res = stat(pt,&buf);
	if (res<0) return NULL;
	return &buf;
}

int is_file(const char *path){
	struct stat *info = stat_file(path);
	if (!info) return -1;
	if ( S_ISREG(info->st_mode) ) return 1;
	return 0;
}

int is_dir(const char *path){
	struct stat *info = stat_file(path);
	if (!info) return -1;
	if ( S_ISDIR(info->st_mode) ) return 1;
	return 0;
}

int is_symlink(const char *path){
	struct stat *info = stat_file(path);
	if (!info) return -1;
	if ( S_ISLNK(info->st_mode) ) return 1;
	return 0;
}


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

typedef enum { unknown = 0, file, http, ldap } scheme_t;

typedef struct {
  char *protocol;
  char *host;
  char *port;
  char *path;
  char *user;
  char *password;
  /* only data has to be freed */
  char *data;
} generic_uri_t;

typedef struct {
  scheme_t scheme;
  generic_uri_t *file, *http;
} uri_t;

static void free_uri(uri_t *uri) {
  /* remember that free() already checks for null */
  if (uri) {
    if(uri->file)
      free(uri->file->data);
    free(uri->file);
    if(uri->http)
      free(uri->http->data);
    free(uri->http);
    free(uri);
  }
}

static int parse_generic_uri(const char *in, generic_uri_t **out)
{
  char *p;

  *out = malloc(sizeof(generic_uri_t));
  if (*out == NULL) {
	  WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  memset(*out, 0, sizeof(generic_uri_t));
  p = (*out)->data = strdup(in);
  if ((*out)->data == NULL) {
    free(*out);
    *out = NULL;
    WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  /* get protocol */
  (*out)->protocol = p;
  p = strstr(p, ":/");
  if (p == NULL) {
    free((*out)->data);
    free(*out);
    *out = NULL;
    WLog_ERR(TAG, "no protocol defined");
    return -1;
  }
  *p = 0;
  p += 2;
  /* distinguish between network path and absolute path */
  if (p[0] != '/') {
    /* get absolute path */
    (*out)->path = (p - 1);
  } else {
    /* get authority and path */
    (*out)->path = strpbrk(p + 1, "/?");
    if ((*out)->path == NULL) {
      (*out)->path = "/";
      (*out)->host = p + 1;
    } else {
      (*out)->host = p;
      memmove(p, p + 1, (*out)->path - p);
      *((*out)->path - 1) = 0;
    }
    /* split authority */
    p = strchr((*out)->host, '@');
    if (p != NULL) {
      (*out)->user = (*out)->host;
      *p++ = 0;
      (*out)->host = p;
    }
    /* split host */
    p = strchr((*out)->host, ':');
    if (p != NULL) {
      *p++ = 0;
      (*out)->port = p;
    }
    /* split user */
    if ((*out)->user) {
      p = strchr((*out)->user, ':');
      if (p != NULL) {
        *p++ = 0;
        (*out)->password = p;
      }
    }
  }
  WLog_DBG(TAG, "protocol = [%s]", (*out)->protocol);
  WLog_DBG(TAG, "user = [%s]", (*out)->user);
  WLog_DBG(TAG, "password = [%s]", (*out)->password);
  WLog_DBG(TAG, "host = [%s]", (*out)->host);
  WLog_DBG(TAG, "port = [%s]", (*out)->port);
  WLog_DBG(TAG, "path = [%s]", (*out)->path);
  return 0;
}

static int parse_uri(const char *str, uri_t **uri)
{
  int rv;

  *uri = malloc(sizeof(uri_t));
  if (*uri == NULL) {
	  WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  memset(*uri, 0, sizeof(uri_t));
  /* parse uri depending on the scheme */
  if (strchr(str, ':') == NULL) {
	  WLog_ERR(TAG, "no scheme defined");
    rv = -1;
  } else if (!strncmp(str, "file:", 5)) {
    (*uri)->scheme = file;
    rv = parse_generic_uri(str, &(*uri)->file);
    if (rv != 0)
    	WLog_ERR(TAG, "parse_generic_uri() failed: %s", get_error());
  } else if (!strncmp(str, "http:", 5)) {
    (*uri)->scheme = http;
    rv = parse_generic_uri(str, &(*uri)->http);
    if (rv != 0)
    	WLog_ERR(TAG, "parse_generic_uri() failed: %s", get_error());
  } else {
    (*uri)->scheme = unknown;
    rv = 0;
  }
  if (rv != 0)
    free_uri(*uri);
  return rv;
}

static int get_file(uri_t *uri, unsigned char **data, ssize_t * length)
{
  int fd;
  ssize_t len, rv;

  *length = 0;
  *data = NULL;
  /* open file */
  WLog_DBG(TAG, "opening...");
  fd = open(uri->file->path, O_RDONLY);
  if (fd == -1) {
    WLog_ERR(TAG, "open() failed: %s", strerror(errno));
    return -1;
  }
  /* get file size and allocate memory */
  *length = (ssize_t) lseek(fd, 0, SEEK_END);
  if (*length == -1) {
    close(fd);
    WLog_ERR(TAG, "lseek() failed: %s", strerror(errno));
    return -1;
  }
  *data = malloc(*length);
  if (*data == NULL) {
    close(fd);
    WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  lseek(fd, 0, SEEK_SET);
  /* read data */
  WLog_DBG(TAG, "reading...");
  len = 0;
  while (len < *length) {
    rv = read(fd, *data + len, *length - len);
    if (rv <= 0) {
      free(*data);
      close(fd);
      WLog_ERR(TAG, "read() failed: %s", strerror(errno));
      return -1;
    }
    len += rv;
  }
  /* close file and exit */
  close(fd);
  return 0;
}

static int get_http(uri_t *uri, unsigned char **data, size_t *length, int rec_level)
{
  int rv, sock, i, j;
  struct addrinfo hint = { 0, PF_UNSPEC, SOCK_STREAM, 0, 0, NULL, NULL, NULL };
  struct addrinfo *info;
  char *request;
  unsigned char *buf;
  ssize_t len, bufsize;

  *length = 0;
  *data = NULL;
  /* get host address and port */
  if (uri->http->port == NULL)
    uri->http->port = "80";
  rv = getaddrinfo(uri->http->host, uri->http->port, &hint, &info);
  if (rv != 0) {
	  WLog_ERR(TAG, "getaddrinfo() failed: %s", gai_strerror(rv));
    return -1;
  }
  sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
  if (sock == -1) {
    freeaddrinfo(info);
    WLog_ERR(TAG, "socket() failed: %s", strerror(errno));
    return -1;
  }
  WLog_DBG(TAG, "connecting...");
  rv = connect(sock, info->ai_addr, info->ai_addrlen);
  freeaddrinfo(info);
  if (rv == -1) {
    close(sock);
    WLog_ERR(TAG, "connect() failed: %s", strerror(errno));
    return -1;
  }
  /* send http 1.0 request */
  request = malloc(32 + strlen(uri->http->path) + strlen(uri->http->host));
  if (request == NULL) {
    close(sock);
    WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  sprintf(request, "GET %s HTTP/1.0\nHost: %s\n\n\n", uri->http->path, uri->http->host);
  len = strlen(request);
  rv = send(sock, request, len, 0);
  free(request);
  if (rv != len) {
    close(sock);
    WLog_ERR(TAG, "send() failed: %s", strerror(errno));
    return -1;
  }
  /* receive response */
  WLog_DBG(TAG, "receiving...");
  bufsize = 128;
  buf = malloc(bufsize);
  if (buf == NULL) {
    close(sock);
    WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  len = 0;
  do {
    rv = recv(sock, &buf[len], bufsize - len, 0);
    if (rv == -1) {
      close(sock);
      free(buf);
      WLog_ERR(TAG, "recv() failed: %s", strerror(errno));
      return -1;
    }
    len += rv;
    if (len >= bufsize && rv) {
      unsigned char *b = (unsigned char *)realloc(buf, (bufsize <<= 1));
      if (b == NULL) {
        close(sock);
        free(buf);
        WLog_ERR(TAG, "not enough free memory available");
        return -1;
      }
      buf = b;
    }
  } while (rv);
  close(sock);
  /* decode header */
  WLog_DBG(TAG, "decoding...");
  if (sscanf((char *)buf, "HTTP/%d.%d %d", &i, &j, &rv) != 3) {
    free(buf);
    WLog_ERR(TAG, "got a malformed http response from the server");
    return -1;
  }
  /* decode result */
  if (rv == 301 || rv == 302) {
    uri_t *ruri;
    /* extract the url to the new location */
    for (i = 0; i < len - 10 && strncmp((char *)&buf[i], "Location: ", 10); i++);
    i += 10;
    for (j = i; j < len && buf[j] != '\r' && buf[j] != '\n' && buf[j] != ' '; j++);
    buf[j] = 0;
    WLog_DBG(TAG, "redirected to %s", &buf[i]);
    /* maximal 5 redirections are allowed */
    if (rec_level > 5) {
      free(buf);
      WLog_ERR(TAG, "to many redirections occurred");
      return -1;
    }
    rv = parse_uri((char *)&buf[i], &ruri);
    if (rv != 0) {
      free(ruri);
      free(buf);
      WLog_ERR(TAG, "parse_uri() failed: %s", get_error());
      return -1;
    }
    if (ruri->scheme != http) {
      free(ruri);
      free(buf);
      WLog_ERR(TAG, "redirection uri is invalid that is not of the scheme http");
      return -1;
    }
    /* downlaod recursively */
    rv = get_http(ruri, data, length, ++rec_level);
    free_uri(ruri);
    free(buf);
    return rv;
  } else if (rv != 200) {
    free(buf);
    WLog_ERR(TAG, "http get command failed with error %d", rv);
    return -1;
  }
  /* ... skip rest of the header */
  for (i = 0; i < len; i++) {
    if (i < len - 2 && !strncmp((char *) &buf[i], "\n\n", 2)) {
      i += 2;
      break;
    }
    if (i < len - 4 && !strncmp((char *)&buf[i], "\r\n\r\n", 4)) {
      i += 4;
      break;
    }
  }
  /* copy data */
  *length = len - i;
  if (*length == 0) {
    free(buf);
    WLog_ERR(TAG, "no data received");
    return -1;
  }
  *data = malloc(*length);
  if (*data == NULL) {
    free(buf);
    WLog_ERR(TAG, "not enough free memory available");
    return -1;
  }
  memcpy(*data, &buf[i], *length);
  free(buf);
  return 0;
}

int get_from_uri(const char *str, unsigned char **data, size_t *length)
{
  int rv;
  uri_t *uri;

  /* parse uri */
  WLog_DBG(TAG, "parsing uri:");
  rv = parse_uri(str, &uri);
  if (rv != 0) {
    free(uri);
    WLog_ERR(TAG, "parse_uri() failed: %s", get_error());
    return -1;
  }
  /* download data depending on the scheme */
  switch (uri->scheme) {
    case file:
      rv = get_file(uri, data, (ssize_t *) length);
      if (rv != 0)
    	  WLog_ERR(TAG, "get_file() failed: %s", get_error());
      break;
    case http:
      rv = get_http(uri, data, length, 0);
      if (rv != 0)
    	  WLog_ERR(TAG, "get_http() failed: %s", get_error());
      break;
	case unknown:
    default:
    	WLog_ERR(TAG, "unsupported protocol");
      rv = -1;
  }
  free_uri(uri);
  return rv;
}
