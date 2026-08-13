/*
 * Copyright (c) 2026 OpenFortiVPN Manager contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "url.h"

#include <stdio.h>
#include <string.h>

static int assert_encoded(const char *input, const char *expected)
{
	char encoded[256];

	url_encode(encoded, input);
	if (strcmp(encoded, expected) == 0)
		return 0;

	fprintf(stderr, "unexpected URL encoding\n");
	return 1;
}

int main(void)
{
	int failures = 0;

	failures += assert_encoded("safe-Az09_~.", "safe-Az09_~.");
	failures += assert_encoded("space and+percent%", "space%20and%2Bpercent%25");
	failures += assert_encoded("A\344\270\255B", "A%E4%B8%ADB");

	return failures == 0 ? 0 : 1;
}
