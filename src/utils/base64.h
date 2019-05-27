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

#ifndef PUNICA_UTILS_BASE64_H
#define PUNICA_UTILS_BASE64_H

#include <stdint.h>

size_t base64_encoded_length(size_t data_length);
size_t base64_decoded_length(size_t base64_length);

int base64_encode(const uint8_t *data, size_t length,
                  char *base64_data, size_t *base64_length);
int base64_decode(const char *base64_data, size_t base64_length,
                  uint8_t *data, size_t *length);

#endif /* PUNICA_UTILS_BASE64_H */
