/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2018 8devices
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "logging.h"

static logging_settings_t logging_settings;

int logging_init(logging_settings_t *settings)
{
    memcpy(&logging_settings, settings, sizeof(logging_settings_t));
    log_message(LOG_LEVEL_TRACE, "Logging timestamp: %s\n", logging_settings.timestamp ? "ON" : "OFF");
    log_message(LOG_LEVEL_TRACE, "Logging level set to %d\n", logging_settings.level);

    if (logging_settings.level > LOG_LEVEL_TRACE)
    {
        log_message(LOG_LEVEL_WARN, "Unexpected high log level \"%d\".\n", logging_settings.level);
    }

    return 0;
}

int log_message(logging_level_t level, char *format, ...)
{
    struct timeval time_timeval;
    time_t time_time;
    struct tm *time_tm;
    char time_buffer[64];

    static size_t stdout_chars = 0, stderr_chars = 0;
    FILE *stream;
    size_t *stream_chars;
    int status = 0;
    va_list arg_ptr;
    va_start(arg_ptr, format);

    if (level > logging_settings.level)
    {
        status = 1;
        goto exit;
    }
    else if (level <= LOG_LEVEL_ERROR)
    {
        stream = stderr;
        stream_chars = &stderr_chars;
    }
    else
    {
        stream = stdout;
        stream_chars = &stdout_chars;
    }

    if (logging_settings.timestamp && *stream_chars == 0)
    {
        gettimeofday(&time_timeval, NULL);

        if (logging_settings.human_readable_timestamp)
        {
            time_time = time_timeval.tv_sec;
            time_tm = localtime(&time_time);

            strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_tm);
            fprintf(stream, "%s.%03lu ", time_buffer, time_timeval.tv_usec / 1000);
        }
        else
        {
            fprintf(stream, "%lu.%03lu ", time_timeval.tv_sec, time_timeval.tv_usec / 1000);
        }
    }

    *stream_chars += vfprintf(stream, format, arg_ptr);

    if (format[strlen(format) - 1] == '\n')
    {
        *stream_chars = 0;
    }

exit:
    va_end(arg_ptr);
    return status;
}
