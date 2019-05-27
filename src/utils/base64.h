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

/**
 * Calculate encoded base64 buffer length.
 *
 * This function returns maximum encoded base64 buffer length.
 * NOTE: Includes padding length.
 * NOTE: Doesn't include NULL terminator to the length.
 *
 * @param base64_length Encoded buffer length.
 *
 * @return Maximum length of output buffer length for base64_encode.
 */
size_t base64_encoded_length(size_t data_length);

/**
 * Calculate decoded base64 buffer length.
 *
 * This function returns maximum decoded base64 buffer length.
 *
 * @param base64_length Encoded buffer length.
 *
 * @return Maximum length of output buffer length for base64_decode.
 */
size_t base64_decoded_length(size_t base64_length);

/**
 * Encode base64 buffer.
 *
 * This function returns result buffer and its length through parameters.
 *
 * @param data Pointer to data buffer.
 * @param length Data buffer length.
 * @param base64_data Pointer to buffer, where encoded buffer will be stored.
 * @param base64_length Pointer to encoded buffer length.
 *
 * @return 0 on success, -1 on error.
 */
int base64_encode(const uint8_t *data, size_t length,
                  char *base64_data, size_t *base64_length);

/**
 * Decode base64 buffer.
 *
 * This function returns result buffer and its length through parameters.
 *
 * @param base64_data Pointer to encoded base64 buffer.
 * @param base64_length Base64 buffer length.
 * @param data Pointer to buffer, where decoded buffer will be stored.
 * @param length Pointer to decoded buffer length.
 *
 * @return 0 on success, -1 on error.
 */
int base64_decode(const char *base64_data, size_t base64_length,
                  uint8_t *data, size_t *length);

#endif /* PUNICA_UTILS_BASE64_H */
