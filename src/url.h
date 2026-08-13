/*
 * Copyright (c) 2015 Adrien Vergé
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef OPENFORTIVPN_URL_H
#define OPENFORTIVPN_URL_H

/*
 * URL-encodes UTF-8 bytes for HTTP form requests.
 *
 * The destination buffer must be at least strlen(source) * 3 + 1 bytes.
 */
static inline void url_encode(char *destination, const char *source)
{
	static const char hex[] = "0123456789ABCDEF";

	while (*source != '\0') {
		unsigned char byte = (unsigned char)*source;
		int unreserved = (byte >= 'A' && byte <= 'Z') ||
		                 (byte >= 'a' && byte <= 'z') ||
		                 (byte >= '0' && byte <= '9') ||
		                 byte == '-' || byte == '_' || byte == '.' ||
		                 byte == '~';

		if (unreserved) {
			*destination++ = (char)byte;
		} else {
			*destination++ = '%';
			*destination++ = hex[byte >> 4];
			*destination++ = hex[byte & 15];
		}
		source++;
	}
	*destination = '\0';
}

#endif
