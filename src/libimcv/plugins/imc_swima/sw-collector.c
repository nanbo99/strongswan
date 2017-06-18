/*
 * Copyright (C) 2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#ifdef HAVE_SYSLOG
# include <syslog.h>
#endif

#include <library.h>
#include <utils/debug.h>
#include <utils/lexparser.h>

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = TRUE;

/**
 * sw_collector dbg function
 */
static void sw_collector_dbg(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= debug_level)
	{
		if (!stderr_quiet)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
			va_end(args);
		}

#ifdef HAVE_SYSLOG
		{
			int priority = LOG_INFO;
			char buffer[8192];
			char *current = buffer, *next;

			/* write in memory buffer first */
			va_start(args, fmt);
			vsnprintf(buffer, sizeof(buffer), fmt, args);
			va_end(args);

			/* do a syslog with every line */
			while (current)
			{
				next = strchr(current, '\n');
				if (next)
				{
					*(next++) = '\0';
				}
				syslog(priority, "%s\n", current);
				current = next;
			}
		}
#endif /* HAVE_SYSLOG */
	}
}

/**
 * atexit handler
 */
static void cleanup(void)
{
	library_deinit();
#ifdef HAVE_SYSLOG
	closelog();
#endif
}

/**
 * Define auxiliary package_t list item object
 */
typedef struct package_t package_t;

struct package_t {
	char *package;
	char *version;
	char *old_version;
	char *sw_id;
	char *old_sw_id;
};

/**
 * Replaces invalid character by a valid one
 */
static void sanitize_uri(char *uri, char a, char b)
{
	char *pos = uri;

	while (TRUE)
	{
		pos = strchr(pos, a);
		if (!pos)
		{
			break;
		}
		*pos = b;
		pos++;
	}
}

/**
 * Create software identifier
 */
char* create_sw_id(char *tag_creator, char *os, char *package, char *version)
{
	char *pos, *sw_id;
	size_t len;

	/* Remove architecture from package name */
	pos = strchr(package, ':');
	len = pos ? (pos - package) : strlen(package);

	/* Build software identifier */
	asprintf(&sw_id, "%s__%s-%.*s%s%s", tag_creator, os, len, package,
										strlen(version) ? "-" : "", version);
	sanitize_uri(sw_id, ':', '~');
	sanitize_uri(sw_id, '+', '~');

	return sw_id;
}

/**
 * Create package_t list item object
 */
static package_t* create_package(char* tag_creator, char *os, chunk_t package,
								 chunk_t version, chunk_t old_version)
{
	package_t *this;

	INIT(this,
		.package = strndup(package.ptr, package.len),
		.version = strndup(version.ptr, version.len),
		.old_version = strndup(old_version.ptr, old_version.len),
	)

	this->sw_id = create_sw_id(tag_creator, os, this->package, this->version);
	if (old_version.len)
	{
		this->old_sw_id = create_sw_id(tag_creator, os, this->package,
									   this->old_version);
	}

	return this;
}

/**
 * Free package_t list item object
 */
static void free_package(package_t *this)
{
	free(this->package);
	free(this->version);
	free(this->old_version);
	free(this->sw_id);
	free(this->old_sw_id);
	free(this);
}

/**
 * Extract package names and versions from argument list
 */
static bool extract_packages(chunk_t args, linked_list_t *list)
{
	chunk_t item, package, version, old_version;
	package_t *p;

	eat_whitespace(&args);

	while (extract_token(&item, ')', &args))
	{
		/* extract package name */
		if (!extract_token(&package, ' ', &item))
		{
			fprintf(stderr, "version not found.\n");
			return FALSE;
		}
		item = chunk_skip(item, 1);

		/* extract versions */
		version = old_version = chunk_empty;

		if (item.len > 0)
		{
			if (extract_token(&version, ',', &item))
			{
				eat_whitespace(&item);
				if (!match("automatic", &item))
				{
					old_version = item;
				}
			}
			else
			{
				version = item;
			}
		}
		p = create_package("strongswan.org", "Ubuntu_16.04-x86_64", package,
							version, old_version);
		list->insert_last(list, p);

		if (old_version.len)
		{
			printf("    %s (%s, %s)\n", p->package, p->version, p->old_version);
			printf("      %s\n", p->sw_id);
			printf("      %s\n", p->old_sw_id);
		}
		else
		{
			printf("    %s (%s)\n", p->package, p->version);
			printf("      %s\n", p->sw_id);
		}

		if (args.len < 2)
		{
			break;
		}
		args = chunk_skip(args, 2);
	}
	return TRUE;
}

/**
 * Handle an Install event
 */
static bool install_handler(database_t *db, chunk_t args, uint32_t eid)
{
	enumerator_t *enumerator, *e;
	linked_list_t *list;
	package_t *p;
	uint32_t sw_id;
	bool success = FALSE;

	printf("  Install:\n");
	list = linked_list_create();
	if (!extract_packages(args, list))
	{
		goto end;
	}

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &p))
	{
		/* Does software identifier already exist in database? */
		e = db->query(db,
			"SELECT id FROM sw_identifiers where name = ?",
			DB_TEXT, p->sw_id, DB_UINT);
		if (!e)
		{
			fprintf(stderr, "database query for sw_identifier failed\n");
			enumerator->destroy(enumerator);
			goto end;
		}
		if (!e->enumerate(e, &sw_id))
		{
			sw_id = 0;
		}
		e->destroy(e);

		if (sw_id)
		{
			if (1 != db->execute(db, NULL,
					"UPDATE sw_identifiers SET installed = 1 WHERE id = ?",
					 DB_UINT, sw_id))
			{
				fprintf(stderr, "unable to update sw_id status in database.\n");
				goto end;
			}
		}
		else
		{
			if (1 != db->execute(db, &sw_id,
					"INSERT INTO sw_identifiers "
					"(name, package, version, source, installed) VALUES "
					"(?, ?, ?, 1, 1)",
					 DB_TEXT, p->sw_id, DB_TEXT, p->package, DB_TEXT, p->version))
			{
				fprintf(stderr, "unable to insert sw_id into database.\n");
				goto end;
			}
		}

		/* Add software identifier event to database */
		if (1 != db->execute(db, NULL,
				"INSERT INTO sw_events (eid, sw_id, action) VALUES (?, ?, 1)",
				 DB_UINT, eid, DB_UINT, sw_id))
		{
			fprintf(stderr, "unable to insert sw_event into database.\n");
			goto end;
		}
	}
	enumerator->destroy(enumerator);
	success = TRUE;

end:
	list->destroy_function(list, (void*)free_package);
	return success;
}

/**
 * Handle an Upgrade event
 */
static bool upgrade_handler(database_t *db, chunk_t args, uint32_t eid)
{
	linked_list_t *list;
	bool success = FALSE;

	printf("  Upgrade:\n");
	list = linked_list_create();
	if (!extract_packages(args, list))
	{
		goto end;
	}
	success = TRUE;

end:
	list->destroy_function(list, (void*)free_package);
	return success;
}

/**
 * Handle a Remove event
 */
static bool remove_handler(database_t *db, chunk_t args, uint32_t eid)
{
	linked_list_t *list;
	bool success = FALSE;

	printf("  Remove:\n");
	list = linked_list_create();
	if (!extract_packages(args, list))
	{
		goto end;
	}
	success = TRUE;

end:
	list->destroy_function(list, (void*)free_package);
	return success;
}

/**
 * Handle a Purge event
 */
static bool purge_handler(database_t *db, chunk_t args, uint32_t eid)
{
	linked_list_t *list;
	bool success = FALSE;

	printf("  Purge:\n");
	list = linked_list_create();
	if (!extract_packages(args, list))
	{
		goto end;
	}
	success = TRUE;

end:
	list->destroy_function(list, (void*)free_package);
	return success;
}

int main(int argc, char *argv[])
{
	database_t *db;
	uint32_t epoch, eid, e_id;
	char *last_time = NULL, rfc_time[21];
	char *uri, *history_path;
	chunk_t *h, history, line, cmd, t1, t2;
	enumerator_t *e;
	int status = -1;
	bool skip = FALSE;

	
	/* enable sw_collector debugging hook */
	dbg = sw_collector_dbg;
#ifdef HAVE_SYSLOG
	openlog("sw-collector", 0, LOG_DEBUG);
#endif

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL, "sw-collector"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}

	/* load sw-collector plugins */
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "sw-collector.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	/* open history file for reading */
	history_path= lib->settings->get_str(lib->settings, "sw-collector.history",
										 NULL);
	if (!history_path)
	{
		fprintf(stderr, "sw-collector.history path not set.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	h = chunk_map(history_path, FALSE);
	if (!h)
	{
		fprintf(stderr, "opening '%s' failed: %s", history, strerror(errno));
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	history = *h;

	/* connect to sw-collector database */
	uri = lib->settings->get_str(lib->settings, "sw-collector.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "sw-collector.database URI not set.\n");
		chunk_unmap(h);
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "connection to sw-collector database failed.\n");
		chunk_unmap(h);
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	/* retrieve latest event in database */
	e = db->query(db,
			"SELECT epoch, eid, time FROM events ORDER BY time DESC",
			DB_UINT, DB_UINT, DB_TEXT);
	if (!e)
	{
		fprintf(stderr, "database query for event failed\n");
		goto end;
	}
	if (e->enumerate(e, &epoch, &eid, &last_time))
	{
		printf("Last-Event: %s, eid = %u, epoch = %u\n", last_time, eid, epoch);
		last_time = strdup(last_time);
		skip = TRUE;
	}
	else
	{
		rng_t *rng;

		rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
		if (!rng || !rng->get_bytes(rng, sizeof(uint32_t), (uint8_t*)&epoch))
		{
			DESTROY_IF(rng);
			fprintf(stderr, "generating random epoch value failed\n");
			goto end;
		}
		rng->destroy(rng);
		eid = 0;
		fprintf(stderr, "created new epoch = %u\n", epoch);
	}
	e->destroy(e);

	/* parse history file */
	while (fetchline(&history, &line))
	{
		if (line.len == 0)
		{
			continue;
		}
		if (!extract_token(&cmd, ':', &line))
		{
			fprintf(stderr, "terminator symbol ':' not found.\n");
			goto end;
		}
		if (match("Start-Date", &cmd))
		{
			if (!eat_whitespace(&line) || !extract_token(&t1, ' ', &line) ||
				!eat_whitespace(&line) || t1.len != 10 || line.len != 8)
			{
				fprintf(stderr, "unable to parse start-date.\n");
				goto end;
			}
			t2 = line;

			/* Form timestamp according to RFC 3339 (20 characters) */
			snprintf(rfc_time, sizeof(rfc_time), "%.*sT%.*sZ",
					 t1.len, t1.ptr, t2.len, t2.ptr);

			/* have we reached new history entries? */
			if (skip && strcmp(rfc_time, last_time) > 0)
			{
				skip = FALSE;
			}
			if (skip)
			{
				continue;
			}

			/* insert new event into database */
			printf("Start-Date: %s, eid = %u\n", rfc_time, ++eid);

			if (1 != db->execute(db, &e_id,
					"INSERT INTO events (epoch, eid, time) VALUES (?, ?, ?)",
					 DB_UINT, epoch, DB_UINT, eid, DB_TEXT, rfc_time))
			{
				fprintf(stderr, "unable to insert event into database.\n");
				goto end;
			}
		}
		else if (skip)
		{
			/* skip old history entries which have already been processed */
			continue;
		}
		else if (match("Install", &cmd))
		{
			if (!install_handler(db, line, e_id))
			{
				goto end;
			}
		}
		else if (match("Upgrade", &cmd))
		{
			if (!upgrade_handler(db, line, e_id))
			{
				goto end;
			}
		}
		else if (match("Remove", &cmd))
		{
			if (!remove_handler(db, line, e_id))
			{
				goto end;
			}
		}
		else if (match("Purge", &cmd))
		{
			if (!purge_handler(db, line, e_id))
			{
				goto end;
			}
		}
		else if (match("End-Date", &cmd))
		{
			/* Add 10 events at a time for test purposes */
			if (eid % 10 == 0)
			{
				printf("added 10 events.\n");
				goto end;
			}
		}
	}
	status = EXIT_SUCCESS;

end:
	free(last_time);
	chunk_unmap(h);
	db->destroy(db);

	exit(status);
}
